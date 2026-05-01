use bytes::Bytes;
use parking_lot::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusFrame {
    pub index: u64,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapshotState {
    pub last_included_index: u64,
    pub payload: Vec<u8>,
}

pub trait WalStorage: Send + Sync {
    fn append_frame(&self, frame: ConsensusFrame);
    fn get_since(&self, since_index: u64) -> Vec<ConsensusFrame>;
    fn truncate_prefix(&self, upto_inclusive: u64);
    fn last_index(&self) -> u64;
    fn len(&self) -> usize;
}

#[derive(Debug, Default)]
pub struct InMemoryWalStorage {
    frames: RwLock<Vec<ConsensusFrame>>,
    snapshot: RwLock<Option<SnapshotState>>,
}

impl InMemoryWalStorage {
    pub fn set_snapshot(&self, snapshot: SnapshotState) {
        *self.snapshot.write() = Some(snapshot);
    }

    pub fn snapshot(&self) -> Option<SnapshotState> {
        self.snapshot.read().clone()
    }
}

impl WalStorage for InMemoryWalStorage {
    fn append_frame(&self, frame: ConsensusFrame) {
        self.frames.write().push(frame);
    }

    fn get_since(&self, since_index: u64) -> Vec<ConsensusFrame> {
        self.frames
            .read()
            .iter()
            .filter(|f| f.index > since_index)
            .cloned()
            .collect()
    }

    fn truncate_prefix(&self, upto_inclusive: u64) {
        let mut frames = self.frames.write();
        frames.retain(|f| f.index > upto_inclusive);
    }

    fn last_index(&self) -> u64 {
        self.frames
            .read()
            .last()
            .map(|f| f.index)
            .unwrap_or(0)
    }

    fn len(&self) -> usize {
        self.frames.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_append_and_get_since_works() {
        let wal = InMemoryWalStorage::default();
        wal.append_frame(ConsensusFrame {
            index: 1,
            payload: Bytes::from_static(b"a"),
        });
        wal.append_frame(ConsensusFrame {
            index: 2,
            payload: Bytes::from_static(b"b"),
        });

        let frames = wal.get_since(1);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].index, 2);
    }

    #[test]
    fn wal_truncate_prefix_removes_old_frames() {
        let wal = InMemoryWalStorage::default();
        for idx in 1..=4 {
            wal.append_frame(ConsensusFrame {
                index: idx,
                payload: Bytes::from(vec![idx as u8]),
            });
        }

        wal.truncate_prefix(2);
        let frames = wal.get_since(0);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].index, 3);
        assert_eq!(frames[1].index, 4);
    }

    #[test]
    fn snapshot_set_and_get_roundtrip() {
        let wal = InMemoryWalStorage::default();
        wal.set_snapshot(SnapshotState {
            last_included_index: 7,
            payload: b"snap".to_vec(),
        });

        let snapshot = wal.snapshot().expect("snapshot should exist");
        assert_eq!(snapshot.last_included_index, 7);
        assert_eq!(snapshot.payload, b"snap");
    }
}
