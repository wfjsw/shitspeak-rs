use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use super::super::overlay_network::NodeId;
use serde::{Deserialize, Serialize};

use super::{ReplicatedCommand, WalFrame};

pub trait WalStorage {
    type Error;

    fn append_frame(&mut self, index: u64, term: u64, payload: &[u8]) -> Result<(), Self::Error>;
    fn truncate_suffix(&mut self, from_index: u64) -> Result<(), Self::Error>;
}

pub trait SnapshotHandle {
    type Error;

    fn install_snapshot(&mut self, last_included_index: u64, data: &[u8]) -> Result<(), Self::Error>;
    fn read_snapshot(&self) -> Result<Option<Vec<u8>>, Self::Error>;
}

pub trait ReplicatedStateEngine {
    type Error;

    fn apply_committed(&mut self, index: u64, payload: &[u8]) -> Result<(), Self::Error>;
    fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error>;
    fn import_snapshot(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}

pub trait AppliedIndexProvider {
    fn highest_applied_index(&self) -> Option<u64>;
}

pub trait StrictReplicationStorage {
    type Wal: WalStorage<Error = String>;
    type Snapshot: SnapshotHandle<Error = String>;
    type Engine: ReplicatedStateEngine<Error = String> + AppliedIndexProvider;

    fn wal_mut(&mut self) -> &mut Self::Wal;
    fn snapshot_ref(&self) -> &Self::Snapshot;
    fn snapshot_mut(&mut self) -> &mut Self::Snapshot;
    fn engine_ref(&self) -> &Self::Engine;
    fn engine_mut(&mut self) -> &mut Self::Engine;
}

pub trait ConsensusTransport {
    type Error;

    fn send_consensus_frame(&self, target: NodeId, bytes: &[u8]) -> Result<(), Self::Error>;
    fn broadcast_consensus_frame(&self, bytes: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone)]
pub struct JsonFileWalStorage {
    path: PathBuf,
}

impl JsonFileWalStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_all_frames(&self) -> Result<Vec<WalFrame<Vec<u8>>>, String> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|e| format!("open wal for read failed: {e}"))?;
        let reader = BufReader::new(file);

        let mut frames = Vec::new();
        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("read wal line failed: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }

            let row: JsonWalRow = serde_json::from_str(&line)
                .map_err(|e| format!("decode wal row at line {} failed: {e}", line_no + 1))?;
            frames.push(row.into_frame());
        }

        frames.sort_by_key(|f| f.index);
        Ok(frames)
    }

    fn ensure_parent_dir(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create wal parent directory failed: {e}"))?;
        }
        Ok(())
    }

    fn rewrite_frames(&self, frames: &[WalFrame<Vec<u8>>]) -> Result<(), String> {
        self.ensure_parent_dir()?;
        let tmp = self.path.with_extension("jsonl.tmp");

        {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)
                .map_err(|e| format!("open wal temp for rewrite failed: {e}"))?;
            for frame in frames {
                let row = JsonWalRow::from_frame(frame);
                let line = serde_json::to_string(&row)
                    .map_err(|e| format!("encode wal row failed: {e}"))?;
                file.write_all(line.as_bytes())
                    .map_err(|e| format!("write wal row failed: {e}"))?;
                file.write_all(b"\n")
                    .map_err(|e| format!("write wal newline failed: {e}"))?;
            }
            file.sync_data()
                .map_err(|e| format!("sync wal temp failed: {e}"))?;
        }

        fs::rename(&tmp, &self.path).map_err(|e| format!("replace wal file failed: {e}"))?;
        Ok(())
    }
}

impl WalStorage for JsonFileWalStorage {
    type Error = String;

    fn append_frame(&mut self, index: u64, term: u64, payload: &[u8]) -> Result<(), Self::Error> {
        self.ensure_parent_dir()?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("open wal for append failed: {e}"))?;

        let row = JsonWalRow {
            index,
            term,
            payload: payload.to_vec(),
        };
        let line = serde_json::to_string(&row).map_err(|e| format!("encode wal row failed: {e}"))?;

        file.write_all(line.as_bytes())
            .map_err(|e| format!("append wal row failed: {e}"))?;
        file.write_all(b"\n")
            .map_err(|e| format!("append wal newline failed: {e}"))?;
        file.sync_data()
            .map_err(|e| format!("sync wal append failed: {e}"))?;
        Ok(())
    }

    fn truncate_suffix(&mut self, from_index: u64) -> Result<(), Self::Error> {
        let mut frames = self.read_all_frames()?;
        frames.retain(|f| f.index < from_index);
        self.rewrite_frames(&frames)
    }
}

#[derive(Debug, Clone)]
pub struct JsonFileSnapshotStore {
    path: PathBuf,
}

impl JsonFileSnapshotStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn read_snapshot_record(&self) -> Result<Option<SnapshotRecord>, String> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.path).map_err(|e| format!("read snapshot file failed: {e}"))?;
        let record = serde_json::from_slice::<SnapshotRecord>(&bytes)
            .map_err(|e| format!("decode snapshot failed: {e}"))?;
        Ok(Some(record))
    }
}

impl SnapshotHandle for JsonFileSnapshotStore {
    type Error = String;

    fn install_snapshot(&mut self, last_included_index: u64, data: &[u8]) -> Result<(), Self::Error> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create snapshot parent directory failed: {e}"))?;
        }

        let tmp = self.path.with_extension("snapshot.tmp");
        let record = SnapshotRecord {
            last_included_index,
            data: data.to_vec(),
        };
        let encoded = serde_json::to_vec(&record)
            .map_err(|e| format!("encode snapshot failed: {e}"))?;

        {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)
                .map_err(|e| format!("open snapshot temp failed: {e}"))?;
            file.write_all(&encoded)
                .map_err(|e| format!("write snapshot temp failed: {e}"))?;
            file.sync_data()
                .map_err(|e| format!("sync snapshot temp failed: {e}"))?;
        }

        fs::rename(&tmp, &self.path).map_err(|e| format!("replace snapshot file failed: {e}"))?;
        Ok(())
    }

    fn read_snapshot(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.read_snapshot_record()?.map(|r| r.data))
    }
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryStateEngine {
    applied: BTreeMap<u64, Vec<u8>>,
    snapshot: Option<Vec<u8>>,
}

impl InMemoryStateEngine {
    pub fn applied_len(&self) -> usize {
        self.applied.len()
    }

    pub fn highest_applied_index(&self) -> Option<u64> {
        self.applied.keys().next_back().copied()
    }
}

impl AppliedIndexProvider for InMemoryStateEngine {
    fn highest_applied_index(&self) -> Option<u64> {
        InMemoryStateEngine::highest_applied_index(self)
    }
}

impl ReplicatedStateEngine for InMemoryStateEngine {
    type Error = String;

    fn apply_committed(&mut self, index: u64, payload: &[u8]) -> Result<(), Self::Error> {
        self.applied.insert(index, payload.to_vec());
        Ok(())
    }

    fn export_snapshot(&self) -> Result<Vec<u8>, Self::Error> {
        let encoded = serde_json::to_vec(&self.applied)
            .map_err(|e| format!("encode in-memory state snapshot failed: {e}"))?;
        Ok(encoded)
    }

    fn import_snapshot(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let decoded = serde_json::from_slice::<BTreeMap<u64, Vec<u8>>>(data)
            .map_err(|e| format!("decode in-memory state snapshot failed: {e}"))?;
        self.applied = decoded;
        self.snapshot = Some(data.to_vec());
        Ok(())
    }
}

pub fn encode_replicated_command(command: &ReplicatedCommand) -> Result<Vec<u8>, String> {
    serde_json::to_vec(command).map_err(|e| format!("encode replicated command failed: {e}"))
}

pub fn decode_replicated_command(payload: &[u8]) -> Result<ReplicatedCommand, String> {
    serde_json::from_slice(payload).map_err(|e| format!("decode replicated command failed: {e}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonWalRow {
    index: u64,
    term: u64,
    payload: Vec<u8>,
}

impl JsonWalRow {
    fn from_frame(frame: &WalFrame<Vec<u8>>) -> Self {
        Self {
            index: frame.index,
            term: frame.term,
            payload: frame.payload.clone(),
        }
    }

    fn into_frame(self) -> WalFrame<Vec<u8>> {
        WalFrame {
            index: self.index,
            term: self.term,
            payload: self.payload,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub last_included_index: u64,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time must be monotonic enough for tests")
            .as_nanos();
        std::env::temp_dir().join(format!("s2s-{name}-{nanos}"))
    }

    #[test]
    fn command_encode_decode_roundtrip() {
        let cmd = ReplicatedCommand {
            domain: "acl".to_owned(),
            verb: "set".to_owned(),
            payload: vec![9, 8, 7],
        };
        let bytes = encode_replicated_command(&cmd).expect("encode should succeed");
        let out = decode_replicated_command(&bytes).expect("decode should succeed");
        assert_eq!(out.domain, "acl");
        assert_eq!(out.verb, "set");
        assert_eq!(out.payload, vec![9, 8, 7]);
    }

    #[test]
    fn in_memory_state_engine_tracks_applied_index() {
        let mut engine = InMemoryStateEngine::default();
        engine.apply_committed(4, &[1]).expect("apply should work");
        engine.apply_committed(2, &[2]).expect("apply should work");
        assert_eq!(engine.applied_len(), 2);
        assert_eq!(engine.highest_applied_index(), Some(4));
    }

    #[test]
    fn json_wal_append_read_and_truncate() {
        let path = unique_path("wal");
        let mut wal = JsonFileWalStorage::new(&path);

        wal.append_frame(1, 1, &[1, 2]).expect("append 1 should work");
        wal.append_frame(3, 1, &[3]).expect("append 3 should work");
        wal.append_frame(2, 1, &[2]).expect("append 2 should work");

        let frames = wal.read_all_frames().expect("read all should work");
        assert_eq!(frames.iter().map(|f| f.index).collect::<Vec<_>>(), vec![1, 2, 3]);

        wal.truncate_suffix(3).expect("truncate should work");
        let frames = wal.read_all_frames().expect("read after truncate should work");
        assert_eq!(frames.iter().map(|f| f.index).collect::<Vec<_>>(), vec![1, 2]);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn json_snapshot_install_and_read_roundtrip() {
        let path = unique_path("snapshot");
        let mut snapshot = JsonFileSnapshotStore::new(&path);
        snapshot
            .install_snapshot(42, &[5, 6, 7])
            .expect("install snapshot should work");

        let record = snapshot
            .read_snapshot_record()
            .expect("read record should work")
            .expect("record should exist");
        assert_eq!(record.last_included_index, 42);
        assert_eq!(record.data, vec![5, 6, 7]);

        let bytes = snapshot
            .read_snapshot()
            .expect("read snapshot bytes should work")
            .expect("snapshot bytes should exist");
        assert_eq!(bytes, vec![5, 6, 7]);

        let _ = std::fs::remove_file(path);
    }
}
