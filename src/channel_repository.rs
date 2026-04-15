//! `ChannelRepository` — versioned, WAL-persisted, snapshotted channel store.
//!
//! # Persistence
//!
//! When a `storage_dir` is configured:
//!
//! * `<dir>/channels.snapshot.json` — full snapshot of the channel map.
//! * `<dir>/channels.wal.jsonl`     — append-only newline-delimited JSON log.
//!
//! On startup the snapshot is loaded first, then any WAL entries whose
//! `version` is greater than the snapshot version are replayed.  The WAL is
//! then reopened in append mode for new writes.
//!
//! Every mutation appends one JSON line to the WAL and calls `sync_data()`
//! before returning.  This ensures durability even if the process crashes.
//!
//! # S2S / replication stubs
//!
//! `subscribe()`, `get_log_since()`, and `apply_remote_operation()` are
//! present as stubs with the correct signatures so that future S2S code can
//! call them without touching the repository internals.
//!
//! # ACL cache
//!
//! Effective permissions are cached per `(session_id_u64, channel_id)` after
//! first computation.  The cache is invalidated when ACLs change or when a
//! user changes channels.  The actual ACL evaluation logic lives in `acl.rs`;
//! the repository only drives invalidation and cache storage.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use enumflags2::BitFlags;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{broadcast, Mutex, RwLock};

use crate::acl::ACLPermissions;
use crate::channels::{Channel, ChannelPatch};
use crate::acl::ACL;
use crate::errors::ChannelRepoError;

// ─── WAL types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelOperation {
    pub version: u64,
    pub node_id: u16,
    /// Unix timestamp (seconds since epoch) when the operation was created.
    pub timestamp: i64,
    #[serde(flatten)]
    pub op: ChannelOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ChannelOp {
    CreateChannel { channel: Channel },
    UpdateChannel { id: u32, patch: ChannelPatch },
    DeleteChannel { id: u32 },
    AddLink { a: u32, b: u32 },
    RemoveLink { a: u32, b: u32 },
    SetAcls {
        channel_id: u32,
        inherit_acl: bool,
        acls: Vec<ACL>,
    },
}

// ─── Snapshot ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u64,
    saved_at: i64,
    node_id: u16,
    channels: Vec<Channel>,
}

// ─── ChannelRepository ────────────────────────────────────────────────────────

pub struct ChannelRepository {
    node_id: u16,
    channels: RwLock<HashMap<u32, Channel>>,
    version: AtomicU64,
    /// In-memory log for `get_log_since` and future S2S queries.
    log: RwLock<std::collections::VecDeque<Arc<ChannelOperation>>>,
    log_max_entries: usize,
    /// Cached effective permissions: (session_id_u64, channel_id) → perms.
    acl_cache: RwLock<HashMap<(u64, u32), BitFlags<ACLPermissions>>>,
    /// Optional storage directory.
    storage_dir: Option<PathBuf>,
    /// Append-only WAL file handle; `None` when running in-memory.
    wal_file: Option<Mutex<tokio::fs::File>>,
    /// Broadcast channel for S2S subscribers.
    tx: broadcast::Sender<Arc<ChannelOperation>>,
}

// ─── public API ───────────────────────────────────────────────────────────────

impl ChannelRepository {
    // ── Construction ──────────────────────────────────────────────────────

    /// Create an in-memory repository (no persistence).
    pub fn new_in_memory(node_id: u16) -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Self {
            node_id,
            channels: RwLock::new(HashMap::new()),
            version: AtomicU64::new(0),
            log: RwLock::new(std::collections::VecDeque::new()),
            log_max_entries: 10_000,
            acl_cache: RwLock::new(HashMap::new()),
            storage_dir: None,
            wal_file: None,
            tx,
        })
    }

    /// Open (or create) a persisted repository in `storage_dir`.
    ///
    /// Startup sequence:
    /// 1. Load `channels.snapshot.json` (if present).
    /// 2. Replay `channels.wal.jsonl` entries with `version > snapshot_version`.
    /// 3. Reopen the WAL for appending.
    /// 4. Insert root channel (id=0) if missing.
    pub async fn open(node_id: u16, storage_dir: &Path) -> Result<Arc<Self>, ChannelRepoError> {
        tokio::fs::create_dir_all(storage_dir).await?;

        let snapshot_path = storage_dir.join("channels.snapshot.json");
        let wal_path = storage_dir.join("channels.wal.jsonl");

        // ── 1. Load snapshot ─────────────────────────────────────────────
        let (mut channels, mut base_version) = match tokio::fs::read(&snapshot_path).await {
            Ok(data) => {
                let snap: Snapshot = serde_json::from_slice(&data).map_err(|e| {
                    ChannelRepoError::WalCorrupt {
                        line: 0,
                        reason: format!("snapshot corrupt: {e}"),
                    }
                })?;
                let map: HashMap<u32, Channel> =
                    snap.channels.into_iter().map(|c| (c.id, c)).collect();
                (map, snap.version)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (HashMap::new(), 0u64),
            Err(e) => return Err(ChannelRepoError::WalIo(e)),
        };

        // ── 2. Replay WAL ────────────────────────────────────────────────
        let wal_contents = match tokio::fs::read_to_string(&wal_path).await {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(ChannelRepoError::WalIo(e)),
        };

        let mut max_version = base_version;
        for (line_no, line) in wal_contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let op: ChannelOperation = match serde_json::from_str(line) {
                Ok(op) => op,
                Err(e) => {
                    tracing::warn!(
                        "WAL corrupt at line {}: {} — stopping replay here",
                        line_no + 1,
                        e
                    );
                    break;
                }
            };
            if op.version <= base_version {
                continue; // already reflected in snapshot
            }
            apply_op_to_map(&mut channels, &op.op);
            if op.version > max_version {
                max_version = op.version;
            }
        }

        // ── 3. Open WAL for appending ────────────────────────────────────
        let wal_file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .await?;

        // ── 4. Ensure root channel exists ────────────────────────────────
        if !channels.contains_key(&0) {
            let root = Channel::new(0, "Root".to_owned(), 0, 0, None, false);
            channels.insert(0, root);
        }

        let (tx, _) = broadcast::channel(256);

        Ok(Arc::new(Self {
            node_id,
            channels: RwLock::new(channels),
            version: AtomicU64::new(max_version),
            log: RwLock::new(std::collections::VecDeque::new()),
            log_max_entries: 10_000,
            acl_cache: RwLock::new(HashMap::new()),
            storage_dir: Some(storage_dir.to_owned()),
            wal_file: Some(Mutex::new(wal_file)),
            tx,
        }))
    }

    // ── Version ───────────────────────────────────────────────────────────

    pub fn current_version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    // ── Read API ──────────────────────────────────────────────────────────

    pub async fn get_channel(&self, id: u32) -> Option<Channel> {
        self.channels.read().await.get(&id).cloned()
    }

    pub async fn get_all(&self) -> Vec<Channel> {
        self.channels.read().await.values().cloned().collect()
    }

    pub async fn get_children(&self, parent_id: u32) -> Vec<Channel> {
        self.channels
            .read()
            .await
            .values()
            .filter(|c| c.parent_id == Some(parent_id))
            .cloned()
            .collect()
    }

    /// Returns the chain of ancestors for `channel_id`, starting from the
    /// immediate parent up to (and including) the root.
    pub async fn get_ancestors(&self, channel_id: u32) -> Vec<Channel> {
        let channels = self.channels.read().await;
        let mut result = Vec::new();
        let mut current_id = channel_id;
        loop {
            let Some(ch) = channels.get(&current_id) else { break };
            let Some(pid) = ch.parent_id else { break };
            let Some(parent) = channels.get(&pid) else { break };
            result.push(parent.clone());
            current_id = pid;
        }
        result
    }

    // ── Mutation API ──────────────────────────────────────────────────────

    pub async fn create_channel(
        self: &Arc<Self>,
        mut channel: Channel,
    ) -> Result<Channel, ChannelRepoError> {
        let mut channels = self.channels.write().await;

        // Validate parent exists
        if let Some(pid) = channel.parent_id {
            if !channels.contains_key(&pid) {
                return Err(ChannelRepoError::ParentNotFound(pid));
            }
        }

        // Validate name uniqueness within parent
        if channels.values().any(|c| {
            c.parent_id == channel.parent_id && c.name == channel.name && c.id != channel.id
        }) {
            return Err(ChannelRepoError::NameConflict(channel.name.clone()));
        }

        let op = self.make_op(ChannelOp::CreateChannel { channel: channel.clone() });
        channels.insert(channel.id, channel.clone());
        drop(channels);

        self.commit(op).await?;
        Ok(channel)
    }

    pub async fn update_channel(
        self: &Arc<Self>,
        id: u32,
        patch: ChannelPatch,
    ) -> Result<Channel, ChannelRepoError> {
        let mut channels = self.channels.write().await;

        if !channels.contains_key(&id) {
            return Err(ChannelRepoError::NotFound(id));
        }

        // Validate new parent, if changing
        if let Some(new_parent) = patch.parent_id {
            if let Some(pid) = new_parent {
                if !channels.contains_key(&pid) {
                    return Err(ChannelRepoError::ParentNotFound(pid));
                }
                // Ensure we aren't moving into a descendant
                if is_descendant(&channels, pid, id) {
                    return Err(ChannelRepoError::CannotMoveIntoDescendant);
                }
            }
        }

        // Validate new name uniqueness
        if let Some(ref new_name) = patch.name {
            let target_parent = patch
                .parent_id
                .unwrap_or_else(|| channels[&id].parent_id);
            if channels.values().any(|c| {
                c.parent_id == target_parent && &c.name == new_name && c.id != id
            }) {
                return Err(ChannelRepoError::NameConflict(new_name.clone()));
            }
        }

        let op = self.make_op(ChannelOp::UpdateChannel { id, patch: patch.clone() });
        apply_patch(channels.get_mut(&id).unwrap(), &patch);
        let updated = channels[&id].clone();
        drop(channels);

        self.invalidate_acl_cache_for_channel(id).await;
        self.commit(op).await?;
        Ok(updated)
    }

    /// Delete a channel and all its descendants.  Users should be moved to
    /// the parent by the caller before invoking this.
    pub async fn delete_channel(
        self: &Arc<Self>,
        id: u32,
    ) -> Result<Vec<u32>, ChannelRepoError> {
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }
        let mut channels = self.channels.write().await;
        if !channels.contains_key(&id) {
            return Err(ChannelRepoError::NotFound(id));
        }

        // Collect all descendants (BFS)
        let to_delete = collect_subtree(&channels, id);

        for del_id in &to_delete {
            channels.remove(del_id);
        }
        drop(channels);

        let op = self.make_op(ChannelOp::DeleteChannel { id });
        self.invalidate_acl_cache_for_channel(id).await;
        self.commit(op).await?;
        Ok(to_delete)
    }

    pub async fn add_link(
        self: &Arc<Self>,
        a: u32,
        b: u32,
    ) -> Result<(), ChannelRepoError> {
        if a == b {
            return Ok(()); // no-op; callers should reject same-channel links
        }
        let mut channels = self.channels.write().await;
        if !channels.contains_key(&a) {
            return Err(ChannelRepoError::NotFound(a));
        }
        if !channels.contains_key(&b) {
            return Err(ChannelRepoError::NotFound(b));
        }
        channels.get_mut(&a).unwrap().links.insert(b);
        channels.get_mut(&b).unwrap().links.insert(a);
        drop(channels);

        let op = self.make_op(ChannelOp::AddLink { a, b });
        self.commit(op).await?;
        Ok(())
    }

    pub async fn remove_link(
        self: &Arc<Self>,
        a: u32,
        b: u32,
    ) -> Result<(), ChannelRepoError> {
        let mut channels = self.channels.write().await;
        if let Some(ch) = channels.get_mut(&a) {
            ch.links.remove(&b);
        }
        if let Some(ch) = channels.get_mut(&b) {
            ch.links.remove(&a);
        }
        drop(channels);

        let op = self.make_op(ChannelOp::RemoveLink { a, b });
        self.commit(op).await?;
        Ok(())
    }

    pub async fn set_acls(
        self: &Arc<Self>,
        channel_id: u32,
        inherit_acl: bool,
        acls: Vec<ACL>,
    ) -> Result<(), ChannelRepoError> {
        let mut channels = self.channels.write().await;
        let ch = channels
            .get_mut(&channel_id)
            .ok_or(ChannelRepoError::NotFound(channel_id))?;
        ch.inherit_acl = inherit_acl;
        ch.acls = acls.clone();
        drop(channels);

        let op = self.make_op(ChannelOp::SetAcls {
            channel_id,
            inherit_acl,
            acls,
        });
        self.invalidate_acl_cache_for_channel(channel_id).await;
        self.commit(op).await?;
        Ok(())
    }

    // ── ACL cache ─────────────────────────────────────────────────────────

    pub async fn get_cached_permissions(
        &self,
        session_id: u64,
        channel_id: u32,
    ) -> Option<BitFlags<ACLPermissions>> {
        self.acl_cache
            .read()
            .await
            .get(&(session_id, channel_id))
            .copied()
    }

    pub async fn cache_permissions(
        &self,
        session_id: u64,
        channel_id: u32,
        perms: BitFlags<ACLPermissions>,
    ) {
        self.acl_cache
            .write()
            .await
            .insert((session_id, channel_id), perms);
    }

    pub async fn invalidate_acl_cache_for_channel(&self, channel_id: u32) {
        self.acl_cache
            .write()
            .await
            .retain(|(_, cid), _| *cid != channel_id);
    }

    pub async fn invalidate_acl_cache_for_user(&self, session_id: u64) {
        self.acl_cache
            .write()
            .await
            .retain(|(sid, _), _| *sid != session_id);
    }

    // ── Snapshot / compaction ─────────────────────────────────────────────

    /// Write a snapshot to disk and atomically replace the WAL with an empty
    /// file.  This is the compaction step.
    pub async fn save_snapshot(&self) -> Result<(), ChannelRepoError> {
        let Some(ref dir) = self.storage_dir else {
            return Ok(());
        };
        let snapshot_path = dir.join("channels.snapshot.json");
        let snapshot_tmp = dir.join("channels.snapshot.json.tmp");
        let wal_path = dir.join("channels.wal.jsonl");
        let wal_tmp = dir.join("channels.wal.jsonl.tmp");

        let version = self.version.load(Ordering::Acquire);
        let channels: Vec<Channel> = self.channels.read().await.values().cloned().collect();

        let snap = Snapshot {
            version,
            saved_at: chrono::Utc::now().timestamp(),
            node_id: self.node_id,
            channels,
        };
        let json = serde_json::to_vec(&snap).map_err(|e| {
            ChannelRepoError::WalCorrupt {
                line: 0,
                reason: format!("snapshot serialisation error: {e}"),
            }
        })?;

        // Write snapshot atomically
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&snapshot_tmp)
            .await?;
        file.write_all(&json).await?;
        file.sync_data().await?;
        drop(file);
        tokio::fs::rename(&snapshot_tmp, &snapshot_path).await?;

        // Atomically truncate WAL by writing an empty replacement file
        if let Some(ref wal_mutex) = self.wal_file {
            let mut wal = wal_mutex.lock().await;
            // Write empty staging file
            let mut tmp_file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&wal_tmp)
                .await?;
            tmp_file.sync_data().await?;
            drop(tmp_file);
            tokio::fs::rename(&wal_tmp, &wal_path).await?;
            // Reopen the (now empty) WAL for appending
            *wal = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&wal_path)
                .await?;
        }

        Ok(())
    }

    // ── S2S / replication stubs ───────────────────────────────────────────

    /// Subscribe to the stream of committed `ChannelOperation`s.
    /// Used by future S2S replication code.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<ChannelOperation>> {
        self.tx.subscribe()
    }

    /// Return all log entries with `version > since_version`.
    pub async fn get_log_since(&self, since_version: u64) -> Vec<Arc<ChannelOperation>> {
        self.log
            .read()
            .await
            .iter()
            .filter(|op| op.version > since_version)
            .cloned()
            .collect()
    }

    /// Apply an operation that arrived from a remote node.
    ///
    /// The operation is applied to the local in-memory map but **not**
    /// re-appended to the WAL (it is the remote node's WAL entry, not ours).
    /// Idempotent: if `op.version ≤ current_version` the op is silently
    /// dropped.
    pub async fn apply_remote_operation(
        &self,
        op: Arc<ChannelOperation>,
    ) -> Result<(), ChannelRepoError> {
        if op.version <= self.version.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut channels = self.channels.write().await;
        apply_op_to_map(&mut channels, &op.op);
        self.version.fetch_max(op.version, Ordering::AcqRel);
        Ok(())
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn make_op(&self, op: ChannelOp) -> ChannelOperation {
        let version = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        ChannelOperation {
            version,
            node_id: self.node_id,
            timestamp: chrono::Utc::now().timestamp(),
            op,
        }
    }

    async fn commit(&self, op: ChannelOperation) -> Result<(), ChannelRepoError> {
        let op = Arc::new(op);

        // Append to WAL if persistence is enabled
        if let Some(ref wal_mutex) = self.wal_file {
            let mut line = serde_json::to_string(&*op).map_err(|e| {
                ChannelRepoError::WalCorrupt {
                    line: 0,
                    reason: format!("WAL serialisation error: {e}"),
                }
            })?;
            line.push('\n');
            let mut wal = wal_mutex.lock().await;
            wal.write_all(line.as_bytes()).await?;
            wal.sync_data().await?;
        }

        // Maintain in-memory log
        {
            let mut log = self.log.write().await;
            log.push_back(Arc::clone(&op));
            while log.len() > self.log_max_entries {
                log.pop_front();
            }
        }

        // Notify S2S subscribers (ignore error when no receivers)
        let _ = self.tx.send(op);

        Ok(())
    }
}

// ─── free functions used both by open() replay and by mutation methods ────────

/// Apply a `ChannelOp` to the in-memory channel map.
fn apply_op_to_map(channels: &mut HashMap<u32, Channel>, op: &ChannelOp) {
    match op {
        ChannelOp::CreateChannel { channel } => {
            channels.insert(channel.id, channel.clone());
        }
        ChannelOp::UpdateChannel { id, patch } => {
            if let Some(ch) = channels.get_mut(id) {
                apply_patch(ch, patch);
            }
        }
        ChannelOp::DeleteChannel { id } => {
            let to_delete = collect_subtree(channels, *id);
            for del_id in to_delete {
                channels.remove(&del_id);
            }
        }
        ChannelOp::AddLink { a, b } => {
            if let Some(ch) = channels.get_mut(a) {
                ch.links.insert(*b);
            }
            if let Some(ch) = channels.get_mut(b) {
                ch.links.insert(*a);
            }
        }
        ChannelOp::RemoveLink { a, b } => {
            if let Some(ch) = channels.get_mut(a) {
                ch.links.remove(b);
            }
            if let Some(ch) = channels.get_mut(b) {
                ch.links.remove(a);
            }
        }
        ChannelOp::SetAcls {
            channel_id,
            inherit_acl,
            acls,
        } => {
            if let Some(ch) = channels.get_mut(channel_id) {
                ch.inherit_acl = *inherit_acl;
                ch.acls = acls.clone();
            }
        }
    }
}

fn apply_patch(ch: &mut Channel, patch: &ChannelPatch) {
    if let Some(ref name) = patch.name {
        ch.name = name.clone();
    }
    if let Some(pos) = patch.position {
        ch.position = pos;
    }
    if let Some(max) = patch.max_users {
        ch.max_users = max;
    }
    if let Some(ref desc) = patch.description_hash {
        ch.description_hash = desc.clone();
    }
    if let Some(ref pid) = patch.parent_id {
        ch.parent_id = *pid;
    }
}

/// Collect `root_id` and all of its descendants (BFS), returning their IDs.
fn collect_subtree(channels: &HashMap<u32, Channel>, root_id: u32) -> Vec<u32> {
    let mut result = vec![root_id];
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root_id);
    while let Some(id) = queue.pop_front() {
        for ch in channels.values().filter(|c| c.parent_id == Some(id)) {
            result.push(ch.id);
            queue.push_back(ch.id);
        }
    }
    result
}

/// Return `true` if `candidate` is a descendant of `ancestor_id`.
fn is_descendant(channels: &HashMap<u32, Channel>, candidate: u32, ancestor_id: u32) -> bool {
    let mut current = candidate;
    loop {
        if current == ancestor_id {
            return true;
        }
        match channels.get(&current).and_then(|c| c.parent_id) {
            Some(pid) => current = pid,
            None => return false,
        }
    }
}
