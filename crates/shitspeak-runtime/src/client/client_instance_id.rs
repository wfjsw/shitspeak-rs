use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::constants::MAX_NODE_ID;

// 2025-01-01T00:00:00Z. A custom epoch leaves the 42-bit timestamp valid
// through 2164 while preserving every bit of the 12-bit cluster node ID.
const CUSTOM_EPOCH_UNIX_MILLIS: u64 = 1_735_689_600_000;
const SEQUENCE_BITS: u32 = 10;
const NODE_BITS: u32 = 12;
const SEQUENCE_MASK: u64 = (1 << SEQUENCE_BITS) - 1;
const TIMESTAMP_BITS: u32 = 64 - NODE_BITS - SEQUENCE_BITS;
const TIMESTAMP_MASK: u64 = (1 << TIMESTAMP_BITS) - 1;

static PROCESS_GENERATOR: ClientInstanceIdGenerator = ClientInstanceIdGenerator::new();

/// Generates IDs as `[42-bit milliseconds][12-bit node][10-bit sequence]`.
///
/// The atomic state is process-wide so independently constructed repositories
/// cannot collide. Clock rollback and same-millisecond sequence exhaustion move
/// logical time forward instead of blocking or repeating an ID.
///
/// Uniqueness is scoped to one process incarnation. S2S state from a previous
/// process incarnation is fenced and cleared by the node boot epoch before a
/// new incarnation's operations are admitted.
pub(crate) fn next_client_instance_id(node_id: u16) -> u64 {
    PROCESS_GENERATOR.next(node_id)
}

struct ClientInstanceIdGenerator {
    /// Packed logical timestamp and sequence, without the node bits.
    state: AtomicU64,
}

impl ClientInstanceIdGenerator {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }

    fn next(&self, node_id: u16) -> u64 {
        self.next_at(node_id, current_timestamp_millis())
    }

    fn next_at(&self, node_id: u16, timestamp_millis: u64) -> u64 {
        assert!(
            node_id <= MAX_NODE_ID,
            "client instance ID node ID exceeds 12-bit field"
        );
        let physical_timestamp = timestamp_millis.max(1);
        assert!(
            physical_timestamp <= TIMESTAMP_MASK,
            "client instance ID timestamp exceeds 42-bit field"
        );

        let next_state = loop {
            let current = self.state.load(Ordering::Relaxed);
            let logical_timestamp = current >> SEQUENCE_BITS;
            let sequence = current & SEQUENCE_MASK;
            let next = if physical_timestamp > logical_timestamp {
                physical_timestamp << SEQUENCE_BITS
            } else if sequence < SEQUENCE_MASK {
                current + 1
            } else {
                assert!(
                    logical_timestamp < TIMESTAMP_MASK,
                    "client instance ID space exhausted"
                );
                (logical_timestamp + 1) << SEQUENCE_BITS
            };

            if self
                .state
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break next;
            }
        };

        let timestamp = next_state >> SEQUENCE_BITS;
        let sequence = next_state & SEQUENCE_MASK;
        (timestamp << (NODE_BITS + SEQUENCE_BITS))
            | (u64::from(node_id) << SEQUENCE_BITS)
            | sequence
    }
}

fn current_timestamp_millis() -> u64 {
    let unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let relative = unix_millis.saturating_sub(u128::from(CUSTOM_EPOCH_UNIX_MILLIS));
    u64::try_from(relative).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        sync::{Arc, Mutex},
        thread,
    };

    use super::*;

    fn timestamp(id: u64) -> u64 {
        id >> (NODE_BITS + SEQUENCE_BITS)
    }

    fn node(id: u64) -> u16 {
        ((id >> SEQUENCE_BITS) & u64::from(MAX_NODE_ID)) as u16
    }

    fn sequence(id: u64) -> u64 {
        id & SEQUENCE_MASK
    }

    #[test]
    fn layout_preserves_timestamp_node_and_sequence() {
        let generator = ClientInstanceIdGenerator::new();
        let first = generator.next_at(0x0abc, 123_456);
        let second = generator.next_at(0x0abc, 123_456);

        assert_eq!(timestamp(first), 123_456);
        assert_eq!(node(first), 0x0abc);
        assert_eq!(sequence(first), 0);
        assert_eq!(sequence(second), 1);
    }

    #[test]
    fn zero_remains_reserved_for_legacy_wildcard_operations() {
        let generator = ClientInstanceIdGenerator::new();

        assert_ne!(generator.next_at(0, 0), 0);
    }

    #[test]
    fn rollback_keeps_logical_time_monotonic() {
        let generator = ClientInstanceIdGenerator::new();
        let before_rollback = generator.next_at(7, 10_000);
        let after_rollback = generator.next_at(7, 9_000);

        assert!(after_rollback > before_rollback);
        assert_eq!(timestamp(after_rollback), 10_000);
        assert_eq!(sequence(after_rollback), 1);
    }

    #[test]
    fn sequence_exhaustion_advances_logical_time_without_waiting() {
        let generator = ClientInstanceIdGenerator::new();
        let ids: Vec<_> = (0..=SEQUENCE_MASK + 1)
            .map(|_| generator.next_at(9, 500))
            .collect();

        assert_eq!(timestamp(ids[SEQUENCE_MASK as usize]), 500);
        assert_eq!(sequence(ids[SEQUENCE_MASK as usize]), SEQUENCE_MASK);
        assert_eq!(timestamp(ids[SEQUENCE_MASK as usize + 1]), 501);
        assert_eq!(sequence(ids[SEQUENCE_MASK as usize + 1]), 0);
    }

    #[test]
    fn concurrent_generation_is_unique() {
        const THREADS: usize = 8;
        const IDS_PER_THREAD: usize = 2_000;

        let generator = Arc::new(ClientInstanceIdGenerator::new());
        let ids = Arc::new(Mutex::new(Vec::with_capacity(THREADS * IDS_PER_THREAD)));
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let generator = Arc::clone(&generator);
                let ids = Arc::clone(&ids);
                thread::spawn(move || {
                    let generated: Vec<_> = (0..IDS_PER_THREAD)
                        .map(|_| generator.next_at(11, 750))
                        .collect();
                    ids.lock().unwrap().extend(generated);
                })
            })
            .collect();

        for worker in workers {
            worker.join().unwrap();
        }
        let ids = ids.lock().unwrap();
        let unique: HashSet<_> = ids.iter().copied().collect();
        assert_eq!(unique.len(), THREADS * IDS_PER_THREAD);
    }

    #[test]
    fn node_bits_isolate_independent_generators() {
        let left = ClientInstanceIdGenerator::new().next_at(1, 42);
        let right = ClientInstanceIdGenerator::new().next_at(2, 42);

        assert_ne!(left, right);
        assert_eq!(node(left), 1);
        assert_eq!(node(right), 2);
    }

    #[test]
    #[should_panic(expected = "node ID exceeds 12-bit field")]
    fn rejects_node_ids_outside_the_session_id_domain() {
        ClientInstanceIdGenerator::new().next_at(MAX_NODE_ID + 1, 42);
    }
}
