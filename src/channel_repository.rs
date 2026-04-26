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
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use enumflags2::BitFlags;
use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use scc::HashCache;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::sync::{broadcast, Mutex as AsyncMutex};

use crate::acl::ACLPermissions;
use crate::acl::ACL;
use crate::channels::{Channel, ChannelPatch};
use crate::config::Config;
use crate::errors::ChannelRepoError;

#[derive(Debug, Clone, Copy)]
pub struct ChannelRepoTuning {
    pub log_max_entries: usize,
    pub snapshot_every_ops: u64,
    pub snapshot_every_secs: i64,
    pub wal_compaction_expire_count: usize,
}

impl From<&Config> for ChannelRepoTuning {
    fn from(cfg: &Config) -> Self {
        Self {
            log_max_entries: cfg.channel_log_max_entries.max(1),
            snapshot_every_ops: cfg.channel_snapshot_every_ops.max(1),
            snapshot_every_secs: cfg.channel_snapshot_every_secs.max(1),
            wal_compaction_expire_count: cfg.channel_wal_compaction_expire_count,
        }
    }
}

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

impl ChannelOperation {
    /// Convert this log entry into the protobuf `Message` that should be
    /// sent to a subscriber.  Only changed/delta fields are populated;
    /// Mumble clients merge deltas with their existing state.
    pub fn to_message(&self) -> Option<crate::messages::Message> {
        match &self.op {
            ChannelOp::CreateChannel { channel } => Some(channel_to_proto_full(channel)),
            ChannelOp::EditChannel {
                id,
                patch,
                links_add,
                links_remove,
            } => Some(
                crate::messages::encoder::ChannelState {
                    channel_id: Some(*id),
                    parent: patch.parent_id.unwrap_or(None),
                    name: patch.name.clone(),
                    position: patch.position,
                    max_users: patch.max_users,
                    description_hash: patch
                        .description_hash
                        .as_ref()
                        .and_then(|h| h.as_ref().and_then(|h| hex::decode(h).ok())),
                    links_add: links_add.clone(),
                    links_remove: links_remove.clone(),
                    ..Default::default()
                }
                .into(),
            ),
            ChannelOp::UpdateChannel { id, patch } => Some(channel_to_proto_delta(*id, patch)),
            ChannelOp::DeleteChannel { id } => {
                Some(crate::messages::encoder::ChannelRemove { channel_id: *id }.into())
            }
            ChannelOp::AddLink { a, b } => Some(
                crate::messages::encoder::ChannelState {
                    channel_id: Some(*a),
                    links_add: vec![*b],
                    ..Default::default()
                }
                .into(),
            ),
            ChannelOp::RemoveLink { a, b } => Some(
                crate::messages::encoder::ChannelState {
                    channel_id: Some(*a),
                    links_remove: vec![*b],
                    ..Default::default()
                }
                .into(),
            ),
            ChannelOp::SetAcls { .. } => {
                // ACL changes produce PermissionQuery messages, not ChannelState.
                None
            }
        }
    }
}

/// Build a full `ChannelState` encoder message (for CreateChannel).
fn channel_to_proto_full(ch: &Channel) -> crate::messages::Message {
    let links: Vec<u32> = ch.links.iter().copied().collect();
    crate::messages::encoder::ChannelState {
        channel_id: Some(ch.id),
        parent: ch.parent_id,
        name: Some(ch.name.clone()),
        links,
        temporary: Some(ch.is_temporary()),
        position: Some(ch.position),
        description_hash: ch
            .description_hash
            .as_ref()
            .and_then(|h| hex::decode(h).ok()),
        max_users: Some(ch.max_users),
        ..Default::default()
    }
    .into()
}

/// Build a delta `ChannelState` encoder message (for UpdateChannel).
fn channel_to_proto_delta(id: u32, patch: &ChannelPatch) -> crate::messages::Message {
    crate::messages::encoder::ChannelState {
        channel_id: Some(id),
        parent: patch.parent_id.unwrap_or(None),
        name: patch.name.clone(),
        position: patch.position,
        max_users: patch.max_users,
        description_hash: patch
            .description_hash
            .as_ref()
            .and_then(|h| h.as_ref().and_then(|h| hex::decode(h).ok())),
        ..Default::default()
    }
    .into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ChannelOp {
    CreateChannel {
        channel: Channel,
    },
    EditChannel {
        id: u32,
        patch: ChannelPatch,
        links_add: Vec<u32>,
        links_remove: Vec<u32>,
    },
    UpdateChannel {
        id: u32,
        patch: ChannelPatch,
    },
    DeleteChannel {
        id: u32,
    },
    AddLink {
        a: u32,
        b: u32,
    },
    RemoveLink {
        a: u32,
        b: u32,
    },
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
    channels: ParkingRwLock<HashMap<u32, Channel>>,
    version: AtomicU64,
    /// In-memory log for `get_log_since` and future S2S queries.
    log: ParkingRwLock<std::collections::VecDeque<Arc<ChannelOperation>>>,
    log_max_entries: usize,
    /// Cached effective permissions: (session_id_u64, channel_id) → perms.
    /// Lock-free concurrent cache using scc::HashCache.
    acl_cache: HashCache<(u64, u32), BitFlags<ACLPermissions>>,
    /// Optional storage directory.
    storage_dir: Option<PathBuf>,
    /// Append-only WAL file handle; `None` when running in-memory.
    wal_file: Option<AsyncMutex<tokio::fs::File>>,
    /// Number of valid entries currently present in WAL.
    wal_entry_count: AtomicUsize,
    snapshot_every_ops: u64,
    snapshot_every_secs: i64,
    wal_compaction_expire_count: usize,
    /// Broadcast channel for S2S subscribers.
    tx: broadcast::Sender<Arc<ChannelOperation>>,
    /// Optional reference to `ClientRepository` for draining pending ops
    /// after remote channel ops are applied.
    client_repo: ParkingMutex<Option<Arc<crate::client_repository::ClientRepository>>>,
    /// Unix timestamp when the last snapshot compaction succeeded.
    last_snapshot_at: AtomicI64,
}

// ─── public API ───────────────────────────────────────────────────────────────

impl ChannelRepository {
    // ── Construction ──────────────────────────────────────────────────────

    /// Create an in-memory repository (no persistence).
    pub fn new_in_memory(node_id: u16, tuning: ChannelRepoTuning) -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        let mut channels = HashMap::new();
        // Ensure root channel exists
        let root = Channel::new(0, "Root", 0, 0, None);
        channels.insert(0, root);
        Arc::new(Self {
            node_id,
            channels: ParkingRwLock::new(channels),
            version: AtomicU64::new(0),
            log: ParkingRwLock::new(std::collections::VecDeque::new()),
            log_max_entries: tuning.log_max_entries,
            acl_cache: HashCache::new(),
            storage_dir: None,
            wal_file: None,
            wal_entry_count: AtomicUsize::new(0),
            snapshot_every_ops: tuning.snapshot_every_ops,
            snapshot_every_secs: tuning.snapshot_every_secs,
            wal_compaction_expire_count: tuning.wal_compaction_expire_count,
            tx,
            client_repo: ParkingMutex::new(None),
            last_snapshot_at: AtomicI64::new(chrono::Utc::now().timestamp()),
        })
    }

    /// Open (or create) a persisted repository in `storage_dir`.
    ///
    /// Startup sequence:
    /// 1. Load `channels.snapshot.json` (if present).
    /// 2. Replay `channels.wal.jsonl` entries with `version > snapshot_version`.
    /// 3. Reopen the WAL for appending.
    /// 4. Insert root channel (id=0) if missing.
    pub async fn open(
        node_id: u16,
        storage_dir: &Path,
        tuning: ChannelRepoTuning,
    ) -> Result<Arc<Self>, ChannelRepoError> {
        tokio::fs::create_dir_all(storage_dir).await?;

        let snapshot_path = storage_dir.join("channels.snapshot.json");
        let wal_path = storage_dir.join("channels.wal.jsonl");

        // ── 1. Load snapshot ─────────────────────────────────────────────
        let (mut channels, mut base_version) = match tokio::fs::read(&snapshot_path).await {
            Ok(data) => {
                let snap: Snapshot =
                    serde_json::from_slice(&data).map_err(|e| ChannelRepoError::WalCorrupt {
                        line: 0,
                        reason: format!("snapshot corrupt: {e}"),
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
        let mut wal_entry_count: usize = 0;
        let mut log_entries = std::collections::VecDeque::new();
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
            wal_entry_count += 1;

            // Keep an in-memory bounded replay window for S2S catch-up.
            log_entries.push_back(Arc::new(op.clone()));
            while log_entries.len() > tuning.log_max_entries {
                log_entries.pop_front();
            }

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
            let root = Channel::new(0, "Root", 0, 0, None);
            channels.insert(0, root);
        }

        let (tx, _) = broadcast::channel(256);

        Ok(Arc::new(Self {
            node_id,
            channels: ParkingRwLock::new(channels),
            version: AtomicU64::new(max_version),
            log: ParkingRwLock::new(log_entries),
            log_max_entries: tuning.log_max_entries,
            acl_cache: HashCache::new(),
            storage_dir: Some(storage_dir.to_owned()),
            wal_file: Some(AsyncMutex::new(wal_file)),
            wal_entry_count: AtomicUsize::new(wal_entry_count),
            snapshot_every_ops: tuning.snapshot_every_ops,
            snapshot_every_secs: tuning.snapshot_every_secs,
            wal_compaction_expire_count: tuning.wal_compaction_expire_count,
            tx,
            client_repo: ParkingMutex::new(None),
            last_snapshot_at: AtomicI64::new(chrono::Utc::now().timestamp()),
        }))
    }

    // ── Version ───────────────────────────────────────────────────────────

    pub fn current_version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    // ── Read API ──────────────────────────────────────────────────────────

    pub async fn get_channel(&self, id: u32) -> Option<Channel> {
        self.channels.read().get(&id).cloned()
    }

    pub async fn get_all(&self) -> Vec<Channel> {
        self.channels.read().values().cloned().collect()
    }

    /// Return the total number of channels.
    pub async fn len(&self) -> usize {
        self.channels.read().len()
    }

    pub async fn get_children(&self, parent_id: u32) -> Vec<Channel> {
        self.channels
            .read()
            .values()
            .filter(|c| c.parent_id == Some(parent_id))
            .cloned()
            .collect()
    }

    /// Returns the chain of ancestors for `channel_id`, starting from the
    /// immediate parent up to (and including) the root.
    pub async fn get_ancestors(&self, channel_id: u32) -> Vec<Channel> {
        let channels = self.channels.read();
        let mut result = Vec::new();
        let mut current_id = channel_id;
        loop {
            let Some(ch) = channels.get(&current_id) else {
                break;
            };
            let Some(pid) = ch.parent_id else { break };
            let Some(parent) = channels.get(&pid) else {
                break;
            };
            result.push(parent.clone());
            current_id = pid;
        }
        result
    }

    /// Return both a channel and its ancestor chain in a single lock
    /// acquisition.  Avoids the double-lock pattern in ACL evaluation.
    pub async fn get_channel_with_ancestors(&self, channel_id: u32) -> (Option<Channel>, Vec<Channel>) {
        let channels = self.channels.read();
        let channel = channels.get(&channel_id).cloned();
        let mut ancestors = Vec::new();
        let mut current_id = channel_id;
        loop {
            let Some(ch) = channels.get(&current_id) else {
                break;
            };
            let Some(pid) = ch.parent_id else { break };
            let Some(parent) = channels.get(&pid) else {
                break;
            };
            ancestors.push(parent.clone());
            current_id = pid;
        }
        (channel, ancestors)
    }

    // ── Mutation API ──────────────────────────────────────────────────────

    /// Allocate a fresh channel ID.  Temporary channels get bit-31 set.
    pub async fn next_channel_id(&self, temporary: bool) -> u32 {
        let channels = self.channels.read();
        // Find the highest non-temporary ID and increment.
        let max_id = channels
            .keys()
            .filter(|id| **id & 0x8000_0000 == 0)
            .max()
            .copied()
            .unwrap_or(0);
        let base = max_id + 1;
        if temporary {
            base | 0x8000_0000
        } else {
            base
        }
    }

    pub async fn create_channel(
        self: &Arc<Self>,
        mut channel: Channel,
    ) -> Result<Channel, ChannelRepoError> {
        let op = {
            let mut channels = self.channels.write();

            // Validate parent exists
            if let Some(pid) = channel.parent_id {
                if !channels.contains_key(&pid) && pid != 0 {
                    return Err(ChannelRepoError::ParentNotFound(pid));
                }
            }

            // Validate name uniqueness within parent
            if channels.values().any(|c| {
                c.parent_id == channel.parent_id && c.name == channel.name && c.id != channel.id
            }) {
                return Err(ChannelRepoError::NameConflict(channel.name.clone()));
            }

            let op = self.make_op(ChannelOp::CreateChannel {
                channel: channel.clone(),
            });
            channels.insert(channel.id, channel.clone());
            op
        };

        self.commit(op).await?;
        Ok(channel)
    }

    pub async fn update_channel(
        self: &Arc<Self>,
        id: u32,
        patch: ChannelPatch,
    ) -> Result<Channel, ChannelRepoError> {
        let mut channels = self.channels.write();

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
            let target_parent = patch.parent_id.unwrap_or_else(|| channels[&id].parent_id);
            if channels
                .values()
                .any(|c| c.parent_id == target_parent && &c.name == new_name && c.id != id)
            {
                return Err(ChannelRepoError::NameConflict(new_name.clone()));
            }
        }

        let (op, updated) = {
            let op = self.make_op(ChannelOp::UpdateChannel {
                id,
                patch: patch.clone(),
            });
            apply_patch(channels.get_mut(&id).unwrap(), &patch);
            let updated = channels[&id].clone();
            (op, updated)
        };

        self.invalidate_acl_cache_for_channel(id).await;
        self.commit(op).await?;
        Ok(updated)
    }

    pub async fn edit_channel(
        self: &Arc<Self>,
        id: u32,
        patch: ChannelPatch,
        links_add: Vec<u32>,
        links_remove: Vec<u32>,
    ) -> Result<Channel, ChannelRepoError> {
        let updated = {
            let mut channels = self.channels.write();

            if !channels.contains_key(&id) {
                return Err(ChannelRepoError::NotFound(id));
            }

            if let Some(new_parent) = patch.parent_id {
                if let Some(pid) = new_parent {
                    if !channels.contains_key(&pid) {
                        return Err(ChannelRepoError::ParentNotFound(pid));
                    }
                    if is_descendant(&channels, pid, id) {
                        return Err(ChannelRepoError::CannotMoveIntoDescendant);
                    }
                }
            }

            if let Some(ref new_name) = patch.name {
                let target_parent = patch.parent_id.unwrap_or_else(|| channels[&id].parent_id);
                if channels
                    .values()
                    .any(|c| c.parent_id == target_parent && &c.name == new_name && c.id != id)
                {
                    return Err(ChannelRepoError::NameConflict(new_name.clone()));
                }
            }

            for &link_add in &links_add {
                if link_add == id {
                    continue;
                }
                if !channels.contains_key(&link_add) {
                    return Err(ChannelRepoError::NotFound(link_add));
                }
            }

            for &link_add in &links_add {
                if link_add == id {
                    continue;
                }
                channels.get_mut(&id).unwrap().links.insert(link_add);
                if let Some(target) = channels.get_mut(&link_add) {
                    target.links.insert(id);
                }
            }

            for &link_remove in &links_remove {
                channels.get_mut(&id).unwrap().links.remove(&link_remove);
                if let Some(target) = channels.get_mut(&link_remove) {
                    target.links.remove(&id);
                }
            }

            apply_patch(channels.get_mut(&id).unwrap(), &patch);
            channels[&id].clone()
        };

        let op = self.make_op(ChannelOp::EditChannel {
            id,
            patch,
            links_add,
            links_remove,
        });
        self.invalidate_acl_cache_for_channel(id).await;
        self.commit(op).await?;
        Ok(updated)
    }

    /// Delete a channel and all its descendants.  Users should be moved to
    /// the parent by the caller before invoking this.
    pub async fn delete_channel(self: &Arc<Self>, id: u32) -> Result<Vec<u32>, ChannelRepoError> {
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }
        let to_delete = {
            let mut channels = self.channels.write();
            if !channels.contains_key(&id) {
                return Err(ChannelRepoError::NotFound(id));
            }

            // Collect all descendants (BFS)
            let to_delete = collect_subtree(&channels, id);

            for del_id in &to_delete {
                channels.remove(del_id);
            }

            to_delete
        };
        let op = self.make_op(ChannelOp::DeleteChannel { id });
        self.invalidate_acl_cache_for_channel(id).await;
        self.commit(op).await?;
        Ok(to_delete)
    }

    pub async fn add_link(self: &Arc<Self>, a: u32, b: u32) -> Result<(), ChannelRepoError> {
        if a == b {
            return Ok(()); // no-op; callers should reject same-channel links
        }
        {
            let mut channels = self.channels.write();
            if !channels.contains_key(&a) {
                return Err(ChannelRepoError::NotFound(a));
            }
            if !channels.contains_key(&b) {
                return Err(ChannelRepoError::NotFound(b));
            }
            channels.get_mut(&a).unwrap().links.insert(b);
            channels.get_mut(&b).unwrap().links.insert(a);
        }

        let op = self.make_op(ChannelOp::AddLink { a, b });
        self.commit(op).await?;
        Ok(())
    }

    pub async fn remove_link(self: &Arc<Self>, a: u32, b: u32) -> Result<(), ChannelRepoError> {
        {
            let mut channels = self.channels.write();
            if let Some(ch) = channels.get_mut(&a) {
                ch.links.remove(&b);
            }
            if let Some(ch) = channels.get_mut(&b) {
                ch.links.remove(&a);
            }
        }

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
        {
            let mut channels = self.channels.write();
            let ch = channels
                .get_mut(&channel_id)
                .ok_or(ChannelRepoError::NotFound(channel_id))?;
            ch.inherit_acl = inherit_acl;
            ch.acls = acls.clone();
        }

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
        self.acl_cache.get(&(session_id, channel_id)).map(|entry| *entry)
    }

    pub async fn cache_permissions(
        &self,
        session_id: u64,
        channel_id: u32,
        perms: BitFlags<ACLPermissions>,
    ) {
        self.acl_cache.put((session_id, channel_id), perms);
    }

    pub async fn invalidate_acl_cache_for_channel(&self, channel_id: u32) {
        // Collect keys to remove (can't modify during iteration)
        let mut keys_to_remove = Vec::new();
        self.acl_cache.scan(|k, _| {
            if k.1 == channel_id {
                keys_to_remove.push(*k);
            }
        });
        // Remove collected keys
        for key in keys_to_remove {
            self.acl_cache.remove(&key);
        }
    }

    pub async fn invalidate_acl_cache_for_user(&self, session_id: u64) {
        // Collect keys to remove (can't modify during iteration)
        let mut keys_to_remove = Vec::new();
        self.acl_cache.scan(|k, _| {
            if k.0 == session_id {
                keys_to_remove.push(*k);
            }
        });
        // Remove collected keys
        for key in keys_to_remove {
            self.acl_cache.remove(&key);
        }
    }

    // ── Snapshot / compaction ─────────────────────────────────────────────

    /// Write a snapshot to disk and lazily compact WAL by expiring the
    /// configured number of oldest entries per compaction pass.
    pub async fn save_snapshot(&self) -> Result<(), ChannelRepoError> {
        let Some(ref dir) = self.storage_dir else {
            return Ok(());
        };
        let snapshot_path = dir.join("channels.snapshot.json");
        let snapshot_tmp = dir.join("channels.snapshot.json.tmp");
        let wal_path = dir.join("channels.wal.jsonl");
        let wal_tmp = dir.join("channels.wal.jsonl.tmp");

        let version = self.version.load(Ordering::Acquire);
        let channels: Vec<Channel> = self.channels.read().values().cloned().collect();

        let snap = Snapshot {
            version,
            saved_at: chrono::Utc::now().timestamp(),
            node_id: self.node_id,
            channels,
        };
        let json = serde_json::to_vec(&snap).map_err(|e| ChannelRepoError::WalCorrupt {
            line: 0,
            reason: format!("snapshot serialisation error: {e}"),
        })?;

        // Write snapshot atomically
        {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&snapshot_tmp)
                .await?;
            file.write_all(&json).await?;
            file.sync_data().await?;
        } // file closed here
        tokio::fs::rename(&snapshot_tmp, &snapshot_path).await?;

        // Compact WAL only when it has grown past the replay window.
        let wal_count = self.wal_entry_count.load(Ordering::Acquire);
        let wal_needs_compaction = wal_count > self.log_max_entries;
        if wal_needs_compaction {
            if let Some(ref wal_mutex) = self.wal_file {
                let mut wal = wal_mutex.lock().await;

                // Expire oldest entries in a best-effort, resource-friendly way.
                // We stream the existing WAL line-by-line and skip the first N lines.
                let expire_n = self
                    .wal_compaction_expire_count
                    .max(1)
                    .min(wal_count.saturating_sub(self.log_max_entries).max(1));

                wal.sync_data().await?;

                let src = tokio::fs::OpenOptions::new().read(true).open(&wal_path).await?;
                let mut reader = tokio::io::BufReader::new(src).lines();
                let mut skipped = 0usize;
                let mut kept = 0usize;

                {
                    let mut tmp_file = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&wal_tmp)
                        .await?;

                    while let Some(line) = reader.next_line().await? {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        if skipped < expire_n {
                            skipped += 1;
                            continue;
                        }
                        tmp_file.write_all(line.as_bytes()).await?;
                        tmp_file.write_all(b"\n").await?;
                        kept += 1;
                    }

                    tmp_file.sync_data().await?;
                }

                tokio::fs::rename(&wal_tmp, &wal_path).await?;
                *wal = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&wal_path)
                    .await?;
                self.wal_entry_count.store(kept, Ordering::Release);
            }
        }

        self.last_snapshot_at
            .store(chrono::Utc::now().timestamp(), Ordering::Release);

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
        let new_version = {
            let mut channels = self.channels.write();
            apply_op_to_map(&mut channels, &op.op);
            let new_version = op.version;
            self.version.fetch_max(new_version, Ordering::AcqRel);
            new_version
        };

        // Notify ClientRepository to drain pending ops whose dep is now satisfied
        let client_repo = self.client_repo.lock().clone();
        if let Some(client_repo) = client_repo {
            client_repo.drain_pending_ops(new_version).await;
        }

        Ok(())
    }

    /// Set the `ClientRepository` reference for cross-repo causal notification.
    pub async fn set_client_repo(
        &self,
        client_repo: Arc<crate::client_repository::ClientRepository>,
    ) {
        *self.client_repo.lock() = Some(client_repo);
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn make_op(&self, op: ChannelOp) -> ChannelOperation {
        ChannelOperation {
            version: 0, // assigned by commit()
            node_id: self.node_id,
            timestamp: chrono::Utc::now().timestamp(),
            op,
        }
    }

    async fn commit(&self, mut op: ChannelOperation) -> Result<(), ChannelRepoError> {
        // Assign version and append to log atomically under the log lock,
        // matching ClientRepository's approach.  The channels lock is
        // released before commit() is called, but version+log ordering is
        // guaranteed by the log lock.
        let op = {
            let mut log = self.log.write();
            let version = self.version.fetch_add(1, Ordering::AcqRel) + 1;
            debug_assert!(
                version < u64::MAX - 1_000_000,
                "ChannelRepository version counter approaching u64::MAX — likely a bug"
            );
            op.version = version;
            let op = Arc::new(op);
            log.push_back(Arc::clone(&op));
            while log.len() > self.log_max_entries {
                log.pop_front();
            }
            op
        };

        // Append to WAL if persistence is enabled (outside log lock —
        // WAL I/O shouldn't block log readers)
        if let Some(ref wal_mutex) = self.wal_file {
            let mut line =
                serde_json::to_string(&*op).map_err(|e| ChannelRepoError::WalCorrupt {
                    line: 0,
                    reason: format!("WAL serialisation error: {e}"),
                })?;
            line.push('\n');
            let mut wal = wal_mutex.lock().await;
            wal.write_all(line.as_bytes()).await?;
            wal.sync_data().await?;
            self.wal_entry_count.fetch_add(1, Ordering::AcqRel);
        }

        let committed_version = op.version;

        // Notify S2S subscribers (ignore error when no receivers)
        let _ = self.tx.send(op);

        // Periodically compact WAL into a snapshot in persisted mode.
        // Trigger on either operation count or elapsed-time threshold.
        // Keep commit success independent from compaction; WAL durability already succeeded.
        let now = chrono::Utc::now().timestamp();
        let last_snapshot = self.last_snapshot_at.load(Ordering::Acquire);
        let ops_due = committed_version % self.snapshot_every_ops == 0;
        let time_due = now.saturating_sub(last_snapshot) >= self.snapshot_every_secs;
        if self.storage_dir.is_some() && (ops_due || time_due) {
            if let Err(e) = self.save_snapshot().await {
                tracing::warn!("channel snapshot compaction failed: {e}");
            }
        }

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
        ChannelOp::EditChannel {
            id,
            patch,
            links_add,
            links_remove,
        } => {
            for link_add in links_add {
                if *link_add == *id {
                    continue;
                }
                if let Some(ch) = channels.get_mut(id) {
                    ch.links.insert(*link_add);
                }
                if let Some(target) = channels.get_mut(link_add) {
                    target.links.insert(*id);
                }
            }
            for link_remove in links_remove {
                if let Some(ch) = channels.get_mut(id) {
                    ch.links.remove(link_remove);
                }
                if let Some(target) = channels.get_mut(link_remove) {
                    target.links.remove(id);
                }
            }
            if let Some(ch) = channels.get_mut(id) {
                apply_patch(ch, patch);
            }
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
