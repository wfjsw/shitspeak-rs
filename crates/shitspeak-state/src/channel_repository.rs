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
//! # S2S / replication
//!
//! `subscribe()`, `get_log_since()`, and `apply_remote_operation()` are the
//! repository boundary used by strict S2S channel replication. Channel deletes
//! are two phase: a pending marker is replicated before the nonce-bearing
//! delete, so stale deletes become semantic no-ops.
//!
//! # ACL cache
//!
//! Effective permissions are cached per `(session_id_u64, client_instance_id,
//! channel_id)` after first computation.  The cache is invalidated when ACLs
//! change or when a user changes channels.  The actual ACL evaluation logic
//! lives in `acl.rs`; the repository only drives invalidation and cache
//! storage.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
use enumflags2::BitFlags;
use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use scc::HashCache;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Mutex as AsyncMutex, broadcast};

use crate::{ACL, ACLPermissions, Channel, ChannelPatch, ChannelRepoError, PendingDeleteState};
use shitspeak_core::{DEFAULT_SERVER_ID, StrictReplicationMetadata, default_server_id};
use shitspeak_messages::messages::{Message, encoder};

const TEMPORARY_CHANNEL_ID_BIT: u32 = 0x8000_0000;

pub type ChannelStateSubscription = broadcast::Receiver<Arc<ChannelOperation>>;

#[async_trait]
pub trait ChannelRepositoryObserver: Send + Sync {
    async fn channel_version_advanced(&self, server_id: &str, channel_version: u64);

    async fn repair_missing_channels(
        &self,
        server_id: &str,
        valid_channel_ids: &HashSet<u32>,
        channel_version: u64,
    ) -> usize;
}

#[derive(Debug, Clone, Copy)]
pub struct ChannelRepoTuning {
    pub log_max_entries: usize,
    pub snapshot_every_ops: u64,
    pub snapshot_every_secs: i64,
    pub wal_compaction_expire_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRootConfig {
    name: String,
}

impl ChannelRootConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

// ─── WAL types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelOperation {
    #[serde(default = "default_server_id")]
    pub server_id: String,
    pub version: u64,
    pub node_id: u16,
    /// Unix timestamp (seconds since epoch) when the operation was created.
    pub timestamp: i64,
    #[serde(default)]
    pub emits_client_message: bool,
    #[serde(flatten)]
    pub op: ChannelOp,
}

impl ChannelOperation {
    pub fn is_root_name_config_update(&self) -> bool {
        matches!(
            &self.op,
            ChannelOp::UpdateChannel { id: 0, patch }
                if patch.name.is_some()
                    && patch.position.is_none()
                    && patch.max_users.is_none()
                    && patch.description_hash.is_none()
                    && patch.parent_id.is_none()
        )
    }

    /// Convert this log entry into the protobuf `Message` that should be
    /// sent to a subscriber.  Only changed/delta fields are populated;
    /// Mumble clients merge deltas with their existing state.
    pub fn to_message(&self) -> Option<Message> {
        match &self.op {
            ChannelOp::CreateChannel { channel } => Some(channel_to_proto_full(channel)),
            ChannelOp::EditChannel {
                id,
                patch,
                links_add,
                links_remove,
            } => Some(
                encoder::ChannelState {
                    channel_id: Some(*id),
                    parent: patch.parent_id.unwrap_or(None),
                    name: patch.name.clone(),
                    position: patch.position,
                    max_users: patch.max_users,
                    description_hash: patch.description_hash.as_ref().and_then(|h| {
                        h.as_ref()
                            .and_then(|h| hex::decode(h).ok().map(bytes::Bytes::from))
                    }),
                    links_add: links_add.clone(),
                    links_remove: links_remove.clone(),
                    ..Default::default()
                }
                .into(),
            ),
            ChannelOp::UpdateChannel { id, patch } => Some(channel_to_proto_delta(*id, patch)),
            ChannelOp::DeleteChannel { id, .. } if self.emits_client_message => {
                Some(encoder::ChannelRemove { channel_id: *id }.into())
            }
            ChannelOp::DeleteChannel { .. } => None,
            ChannelOp::MarkPendingDelete { .. } | ChannelOp::CancelPendingDelete { .. } => None,
            ChannelOp::AddLink { a, b } => Some(
                encoder::ChannelState {
                    channel_id: Some(*a),
                    links_add: vec![*b],
                    ..Default::default()
                }
                .into(),
            ),
            ChannelOp::RemoveLink { a, b } => Some(
                encoder::ChannelState {
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
            ChannelOp::InstallSnapshot { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChannelLogEntry {
    op: Arc<ChannelOperation>,
    strict_metadata: Option<StrictReplicationMetadata>,
}

impl ChannelLogEntry {
    fn new(op: Arc<ChannelOperation>, strict_metadata: Option<StrictReplicationMetadata>) -> Self {
        Self {
            op,
            strict_metadata,
        }
    }

    pub fn op(&self) -> Arc<ChannelOperation> {
        self.op.clone()
    }

    pub fn strict_metadata(&self) -> Option<StrictReplicationMetadata> {
        self.strict_metadata
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChannelWalRecord {
    #[serde(flatten)]
    op: ChannelOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strict_metadata: Option<StrictReplicationMetadata>,
}

impl ChannelWalRecord {
    fn new(op: &ChannelOperation, strict_metadata: Option<StrictReplicationMetadata>) -> Self {
        Self {
            op: op.clone(),
            strict_metadata,
        }
    }
}

/// Build a full `ChannelState` encoder message (for CreateChannel).
fn channel_to_proto_full(ch: &Channel) -> Message {
    let links: Vec<u32> = ch.links.iter().copied().collect();
    encoder::ChannelState {
        channel_id: Some(ch.id),
        parent: ch.parent_id,
        name: Some(ch.name.clone()),
        links,
        temporary: Some(ch.is_temporary()),
        position: Some(ch.position),
        description_hash: ch
            .description_hash
            .as_ref()
            .and_then(|h| hex::decode(h).ok().map(bytes::Bytes::from)),
        max_users: Some(ch.max_users),
        ..Default::default()
    }
    .into()
}

/// Build a delta `ChannelState` encoder message (for UpdateChannel).
fn channel_to_proto_delta(id: u32, patch: &ChannelPatch) -> Message {
    encoder::ChannelState {
        channel_id: Some(id),
        parent: patch.parent_id.unwrap_or(None),
        name: patch.name.clone(),
        position: patch.position,
        max_users: patch.max_users,
        description_hash: patch.description_hash.as_ref().and_then(|h| {
            h.as_ref()
                .and_then(|h| hex::decode(h).ok().map(bytes::Bytes::from))
        }),
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
    MarkPendingDelete {
        id: u32,
        nonce: u64,
        #[serde(default = "default_mark_pending_delete_evict_clients")]
        evict_clients: bool,
    },
    DeleteChannel {
        id: u32,
        nonce: u64,
    },
    CancelPendingDelete {
        id: u32,
        nonce: u64,
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
    /// Synthetic local notification emitted when S2S installs a channel snapshot.
    InstallSnapshot {
        channels: Vec<Channel>,
        removed: Vec<u32>,
    },
}

fn default_mark_pending_delete_evict_clients() -> bool {
    true
}

// ─── Snapshot ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SnapshotChannel {
    #[serde(default = "default_server_id")]
    server_id: String,
    #[serde(flatten)]
    channel: ChannelSnapshotState,
}

#[derive(Clone, Serialize, Deserialize)]
struct ChannelSnapshotState {
    id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    position: i32,
    max_users: u32,
    parent_id: Option<u32>,
    inherit_acl: bool,
    links: HashSet<u32>,
    description_hash: Option<String>,
    acls: Vec<ACL>,
    #[serde(default)]
    pending_delete: Option<PendingDeleteState>,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    #[serde(default)]
    version: u64,
    #[serde(default)]
    versions: HashMap<String, u64>,
    #[serde(default)]
    history_freshness: HashMap<String, i64>,
    saved_at: i64,
    node_id: u16,
    channels: Vec<SnapshotChannel>,
}

// ─── ChannelRepository ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct CachedAclPermissions {
    channel_acl_generation: u64,
    client_acl_generation: u64,
    explicit_enter_deny_overrides_write: bool,
    permissions: BitFlags<ACLPermissions>,
}

#[derive(Debug, Clone, Default)]
struct LinkTopology {
    groups_by_channel: HashMap<u32, Arc<[u32]>>,
}

impl LinkTopology {
    fn from_channels(channels: &HashMap<u32, Channel>) -> Self {
        let mut adjacency: HashMap<u32, HashSet<u32>> = HashMap::new();

        for (&id, channel) in channels {
            for &linked_id in &channel.links {
                if linked_id == id || !channels.contains_key(&linked_id) {
                    continue;
                }
                adjacency.entry(id).or_default().insert(linked_id);
                adjacency.entry(linked_id).or_default().insert(id);
            }
        }

        let mut groups_by_channel = HashMap::new();
        let mut visited = HashSet::new();
        for &start in adjacency.keys() {
            if !visited.insert(start) {
                continue;
            }

            let mut component = Vec::new();
            let mut queue = VecDeque::new();
            queue.push_back(start);

            while let Some(id) = queue.pop_front() {
                component.push(id);
                if let Some(neighbors) = adjacency.get(&id) {
                    for &next in neighbors {
                        if visited.insert(next) {
                            queue.push_back(next);
                        }
                    }
                }
            }

            if component.len() <= 1 {
                continue;
            }

            component.sort_unstable();
            let group = Arc::<[u32]>::from(component.into_boxed_slice());
            for &id in group.iter() {
                groups_by_channel.insert(id, Arc::clone(&group));
            }
        }

        Self { groups_by_channel }
    }

    fn group_for(&self, channel_id: u32) -> Option<Arc<[u32]>> {
        self.groups_by_channel.get(&channel_id).cloned()
    }

    fn remove_deleted_channels(&mut self, channels: &HashMap<u32, Channel>, deleted_ids: &[u32]) {
        let deleted_ids: HashSet<u32> = deleted_ids.iter().copied().collect();
        let mut affected_ids = HashSet::new();

        for deleted_id in &deleted_ids {
            if let Some(group) = self.groups_by_channel.get(deleted_id) {
                for &member_id in group.iter() {
                    if !deleted_ids.contains(&member_id) && channels.contains_key(&member_id) {
                        affected_ids.insert(member_id);
                    }
                }
            }
        }

        for deleted_id in &deleted_ids {
            self.groups_by_channel.remove(deleted_id);
        }
        if affected_ids.is_empty() {
            return;
        }

        for affected_id in &affected_ids {
            self.groups_by_channel.remove(affected_id);
        }

        let mut visited = HashSet::new();
        for &start in &affected_ids {
            if !visited.insert(start) {
                continue;
            }

            let mut component = Vec::new();
            let mut queue = VecDeque::new();
            queue.push_back(start);

            while let Some(id) = queue.pop_front() {
                component.push(id);
                let Some(channel) = channels.get(&id) else {
                    continue;
                };
                for &next in &channel.links {
                    if affected_ids.contains(&next) && visited.insert(next) {
                        queue.push_back(next);
                    }
                }
            }

            if component.len() <= 1 {
                continue;
            }

            component.sort_unstable();
            let group = Arc::<[u32]>::from(component.into_boxed_slice());
            for &id in group.iter() {
                self.groups_by_channel.insert(id, Arc::clone(&group));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LinkTopologyEffect {
    Unchanged,
    DeletedChannels(Vec<u32>),
    Rebuild,
}

struct DeleteChannelApplied {
    deleted_ids: Vec<u32>,
    link_topology_effect: LinkTopologyEffect,
}

fn channel_op_affects_link_topology(op: &ChannelOp) -> bool {
    match op {
        ChannelOp::CreateChannel { channel } => !channel.links.is_empty(),
        ChannelOp::EditChannel {
            links_add,
            links_remove,
            ..
        } => !links_add.is_empty() || !links_remove.is_empty(),
        ChannelOp::DeleteChannel { .. } => false,
        ChannelOp::AddLink { .. }
        | ChannelOp::RemoveLink { .. }
        | ChannelOp::InstallSnapshot { .. } => true,
        ChannelOp::UpdateChannel { .. }
        | ChannelOp::MarkPendingDelete { .. }
        | ChannelOp::CancelPendingDelete { .. }
        | ChannelOp::SetAcls { .. } => false,
    }
}

pub struct ChannelRepository {
    node_id: u16,
    root_config: ParkingRwLock<ChannelRootConfig>,
    channels: ParkingRwLock<HashMap<String, HashMap<u32, Channel>>>,
    /// Derived transitive link groups, rebuilt from direct channel links.
    link_topologies: ParkingRwLock<HashMap<String, LinkTopology>>,
    versions: ParkingRwLock<HashMap<String, u64>>,
    /// In-memory log for `get_log_since` and future S2S queries.
    log: ParkingRwLock<std::collections::VecDeque<ChannelLogEntry>>,
    log_max_entries: usize,
    delete_visibility_hints: ParkingRwLock<HashMap<(String, u64), Arc<[u32]>>>,
    /// Bumped whenever channel state can change effective ACL results.
    channel_acl_generation: AtomicU64,
    /// Per-channel ACL generations for targeted channel cache eviction.
    channel_acl_generations: ParkingRwLock<HashMap<(String, u32), u64>>,
    /// Cached effective permissions:
    /// (server_id, session_id_u64, client_instance_id, channel_id) -> entry.
    /// Lock-free concurrent cache using scc::HashCache.
    acl_cache: HashCache<(String, u64, u64, u32), CachedAclPermissions>,
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
    observer: ParkingMutex<Option<Arc<dyn ChannelRepositoryObserver>>>,
    /// Unix timestamp when the last snapshot compaction succeeded.
    last_snapshot_at: AtomicI64,
    history_freshness: ParkingRwLock<HashMap<String, i64>>,
}

// ─── public API ───────────────────────────────────────────────────────────────

impl ChannelRepository {
    // ── Construction ──────────────────────────────────────────────────────

    /// Create an in-memory repository (no persistence).
    pub fn new_in_memory(
        node_id: u16,
        root_config: ChannelRootConfig,
        tuning: ChannelRepoTuning,
    ) -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        let mut channels = HashMap::new();
        channels
            .entry(DEFAULT_SERVER_ID.to_owned())
            .or_insert_with(HashMap::new)
            .insert(0, root_channel(&root_config));
        let mut versions = HashMap::new();
        versions.insert(DEFAULT_SERVER_ID.to_owned(), 0);
        Arc::new(Self {
            node_id,
            root_config: ParkingRwLock::new(root_config),
            channels: ParkingRwLock::new(channels),
            link_topologies: ParkingRwLock::new(HashMap::new()),
            versions: ParkingRwLock::new(versions),
            log: ParkingRwLock::new(std::collections::VecDeque::new()),
            log_max_entries: tuning.log_max_entries,
            delete_visibility_hints: ParkingRwLock::new(HashMap::new()),
            channel_acl_generation: AtomicU64::new(0),
            channel_acl_generations: ParkingRwLock::new(HashMap::new()),
            acl_cache: HashCache::new(),
            storage_dir: None,
            wal_file: None,
            wal_entry_count: AtomicUsize::new(0),
            snapshot_every_ops: tuning.snapshot_every_ops,
            snapshot_every_secs: tuning.snapshot_every_secs,
            wal_compaction_expire_count: tuning.wal_compaction_expire_count,
            tx,
            observer: ParkingMutex::new(None),
            last_snapshot_at: AtomicI64::new(chrono::Utc::now().timestamp()),
            history_freshness: ParkingRwLock::new(HashMap::new()),
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
        root_config: ChannelRootConfig,
        tuning: ChannelRepoTuning,
    ) -> Result<Arc<Self>, ChannelRepoError> {
        tokio::fs::create_dir_all(storage_dir).await?;

        let snapshot_path = storage_dir.join("channels.snapshot.json");
        let wal_path = storage_dir.join("channels.wal.jsonl");

        // ── 1. Load snapshot ─────────────────────────────────────────────
        let (mut channels, mut versions, mut history_freshness) =
            match tokio::fs::read(&snapshot_path).await {
                Ok(data) => {
                    let snap: Snapshot = serde_json::from_slice(&data).map_err(|e| {
                        ChannelRepoError::WalCorrupt {
                            line: 0,
                            reason: format!("snapshot corrupt: {e}"),
                        }
                    })?;
                    let mut map: HashMap<String, HashMap<u32, Channel>> = HashMap::new();
                    for scoped in snap.channels {
                        let channel = scoped.channel.into_channel(&root_config);
                        map.entry(scoped.server_id)
                            .or_default()
                            .insert(channel.id, channel);
                    }
                    let mut versions = snap.versions;
                    if versions.is_empty() {
                        versions.insert(DEFAULT_SERVER_ID.to_owned(), snap.version);
                    }
                    (map, versions, snap.history_freshness)
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    (HashMap::new(), HashMap::new(), HashMap::new())
                }
                Err(e) => return Err(ChannelRepoError::WalIo(e)),
            };

        // ── 2. Replay WAL ────────────────────────────────────────────────
        let wal_contents = match tokio::fs::read_to_string(&wal_path).await {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(ChannelRepoError::WalIo(e)),
        };

        let mut wal_entry_count: usize = 0;
        let mut log_entries = std::collections::VecDeque::new();
        for (line_no, line) in wal_contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record: ChannelWalRecord = match serde_json::from_str(line) {
                Ok(record) => record,
                Err(e) => {
                    tracing::warn!(
                        "WAL corrupt at line {}: {} — stopping replay here",
                        line_no + 1,
                        e
                    );
                    break;
                }
            };
            let op = record.op;
            let strict_metadata = record.strict_metadata;
            wal_entry_count += 1;
            history_freshness
                .entry(op.server_id.clone())
                .and_modify(|freshness| *freshness = (*freshness).max(op.timestamp))
                .or_insert(op.timestamp);

            // Keep an in-memory bounded replay window for S2S catch-up.
            log_entries.push_back(ChannelLogEntry::new(Arc::new(op.clone()), strict_metadata));
            while log_entries.len() > tuning.log_max_entries {
                log_entries.pop_front();
            }

            let base_version = versions.get(&op.server_id).copied().unwrap_or(0);
            if op.version <= base_version {
                continue; // already reflected in snapshot
            }
            let scoped_channels = channels.entry(op.server_id.clone()).or_default();
            ensure_root_channel(scoped_channels, &root_config);
            apply_op_to_map(scoped_channels, &op.op, op.node_id, &root_config);
            versions
                .entry(op.server_id.clone())
                .and_modify(|version| *version = (*version).max(op.version))
                .or_insert(op.version);
        }

        // ── 3. Open WAL for appending ────────────────────────────────────
        let wal_file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .await?;

        // ── 4. Ensure root channel exists per known scope ────────────────
        if channels.is_empty() {
            channels.insert(DEFAULT_SERVER_ID.to_owned(), HashMap::new());
        }
        for scoped_channels in channels.values_mut() {
            ensure_root_channel(scoped_channels, &root_config);
        }
        versions.entry(DEFAULT_SERVER_ID.to_owned()).or_insert(0);
        let link_topologies = rebuild_all_link_topologies(&mut channels);

        let (tx, _) = broadcast::channel(256);

        Ok(Arc::new(Self {
            node_id,
            root_config: ParkingRwLock::new(root_config),
            channels: ParkingRwLock::new(channels),
            link_topologies: ParkingRwLock::new(link_topologies),
            versions: ParkingRwLock::new(versions),
            log: ParkingRwLock::new(log_entries),
            log_max_entries: tuning.log_max_entries,
            delete_visibility_hints: ParkingRwLock::new(HashMap::new()),
            channel_acl_generation: AtomicU64::new(0),
            channel_acl_generations: ParkingRwLock::new(HashMap::new()),
            acl_cache: HashCache::new(),
            storage_dir: Some(storage_dir.to_owned()),
            wal_file: Some(AsyncMutex::new(wal_file)),
            wal_entry_count: AtomicUsize::new(wal_entry_count),
            snapshot_every_ops: tuning.snapshot_every_ops,
            snapshot_every_secs: tuning.snapshot_every_secs,
            wal_compaction_expire_count: tuning.wal_compaction_expire_count,
            tx,
            observer: ParkingMutex::new(None),
            last_snapshot_at: AtomicI64::new(chrono::Utc::now().timestamp()),
            history_freshness: ParkingRwLock::new(history_freshness),
        }))
    }

    // ── Version ───────────────────────────────────────────────────────────

    pub fn current_version(&self) -> u64 {
        self.current_version_in_server(DEFAULT_SERVER_ID)
    }

    pub fn current_version_in_server(&self, server_id: &str) -> u64 {
        self.versions.read().get(server_id).copied().unwrap_or(0)
    }

    pub fn latest_timestamp_in_server(&self, server_id: &str) -> i64 {
        let logged = self
            .log
            .read()
            .iter()
            .filter(|entry| entry.op.server_id == server_id)
            .map(|entry| entry.op.timestamp)
            .max()
            .unwrap_or(0);
        let snapshot = self
            .history_freshness
            .read()
            .get(server_id)
            .copied()
            .unwrap_or(0);
        logged.max(snapshot)
    }

    pub fn channel_acl_generation(&self) -> u64 {
        self.channel_acl_generation.load(Ordering::Acquire)
    }

    pub fn channel_acl_generation_for_channel(&self, server_id: &str, channel_id: u32) -> u64 {
        self.channel_acl_generation
            .load(Ordering::Acquire)
            .wrapping_add(
                self.channel_acl_generations
                    .read()
                    .get(&(server_id.to_owned(), channel_id))
                    .copied()
                    .unwrap_or(0),
            )
    }

    fn bump_channel_acl_generation(&self) {
        self.channel_acl_generation.fetch_add(1, Ordering::AcqRel);
    }

    fn bump_channel_acl_generation_for_channels(
        &self,
        server_id: &str,
        channel_ids: &HashSet<u32>,
    ) {
        if channel_ids.is_empty() {
            return;
        }
        let mut generations = self.channel_acl_generations.write();
        for channel_id in channel_ids {
            generations
                .entry((server_id.to_owned(), *channel_id))
                .and_modify(|generation| *generation = generation.wrapping_add(1))
                .or_insert(1);
        }
    }

    pub fn local_node_id(&self) -> u16 {
        self.node_id
    }

    pub fn root_channel_name(&self) -> String {
        self.root_config.read().name().to_owned()
    }

    pub async fn update_root_channel_config(&self, root_config: ChannelRootConfig) {
        let mut changed_servers = Vec::new();
        {
            let mut current = self.root_config.write();
            if *current == root_config {
                return;
            }
            *current = root_config.clone();
        }
        {
            let mut all_channels = self.channels.write();
            if all_channels.is_empty() {
                all_channels.insert(DEFAULT_SERVER_ID.to_owned(), HashMap::new());
            }
            for (server_id, channels) in all_channels.iter_mut() {
                ensure_root_channel(channels, &root_config);
                if let Some(root) = channels.get_mut(&0) {
                    root.name = root_config.name().to_owned();
                }
                changed_servers.push(server_id.clone());
            }
        }

        let version_by_server = self.versions.read().clone();
        let now = chrono::Utc::now().timestamp();
        for server_id in changed_servers {
            let version = version_by_server.get(&server_id).copied().unwrap_or(0);
            let _ = self.tx.send(Arc::new(ChannelOperation {
                server_id,
                version,
                node_id: self.node_id,
                timestamp: now,
                emits_client_message: true,
                op: ChannelOp::UpdateChannel {
                    id: 0,
                    patch: ChannelPatch {
                        name: Some(root_config.name().to_owned()),
                        position: None,
                        max_users: None,
                        description_hash: None,
                        parent_id: None,
                    },
                },
            }));
        }
    }

    // ── Read API ──────────────────────────────────────────────────────────

    pub async fn get_channel(&self, id: u32) -> Option<Channel> {
        self.get_channel_in_server(DEFAULT_SERVER_ID, id).await
    }

    pub async fn get_channel_in_server(&self, server_id: &str, id: u32) -> Option<Channel> {
        self.channels
            .read()
            .get(server_id)
            .and_then(|channels| channels.get(&id))
            .cloned()
            .or_else(|| (id == 0).then(|| self.root_channel()))
    }

    pub fn existing_channel_ids_in_server(
        &self,
        server_id: &str,
        ids: &HashSet<u32>,
    ) -> HashSet<u32> {
        if ids.is_empty() {
            return HashSet::new();
        }
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return ids.iter().filter(|id| **id == 0).copied().collect();
        };
        ids.iter()
            .filter(|id| **id == 0 || channels.contains_key(*id))
            .copied()
            .collect()
    }

    pub fn delete_visibility_hint_for_operation(
        &self,
        op: &ChannelOperation,
    ) -> Option<Arc<[u32]>> {
        if !matches!(op.op, ChannelOp::DeleteChannel { .. }) || !op.emits_client_message {
            return None;
        }
        self.delete_visibility_hints
            .read()
            .get(&(op.server_id.clone(), op.version))
            .cloned()
    }

    pub async fn subtree_ids_in_server(&self, server_id: &str, root_id: u32) -> Vec<u32> {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return (root_id == 0).then_some(0).into_iter().collect();
        };
        collect_subtree(channels, root_id)
    }

    /// Return the effective linked-channel group for `channel_id`.
    ///
    /// The stored channel links are direct protocol edges. This derived view is
    /// the connected component produced by those edges, so A-B-C makes A and C
    /// effectively linked without materializing an A-C edge.
    pub fn effective_link_group_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> Option<Arc<[u32]>> {
        self.link_topologies
            .read()
            .get(server_id)
            .and_then(|topology| topology.group_for(channel_id))
    }

    /// Returns true if `channel_id` is inside a subtree currently marked for deletion.
    pub async fn is_pending_delete_subtree(&self, channel_id: u32) -> bool {
        self.is_pending_delete_subtree_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn is_pending_delete_subtree_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> bool {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return false;
        };
        let mut current = Some(channel_id);
        while let Some(id) = current {
            let Some(channel) = channels.get(&id) else {
                return false;
            };
            if channel.pending_delete.is_some() {
                return true;
            }
            current = channel.parent_id;
        }
        false
    }

    /// Resolve `channel_id` to the nearest non-pending ancestor, or root.
    pub async fn redirect_pending_delete_target(&self, channel_id: u32) -> u32 {
        self.redirect_pending_delete_target_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn redirect_pending_delete_target_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> u32 {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return 0;
        };
        let mut current = Some(channel_id);
        while let Some(id) = current {
            let Some(channel) = channels.get(&id) else {
                return 0;
            };
            if channel.pending_delete.is_none() {
                return id;
            }
            current = channel.parent_id;
        }
        0
    }

    /// Return the subtree ids if `id` is currently marked with `nonce`.
    pub async fn pending_delete_subtree(&self, id: u32, nonce: u64) -> Vec<u32> {
        self.pending_delete_subtree_in_server(DEFAULT_SERVER_ID, id, nonce)
            .await
    }

    pub async fn pending_delete_subtree_in_server(
        &self,
        server_id: &str,
        id: u32,
        nonce: u64,
    ) -> Vec<u32> {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return Vec::new();
        };
        let Some(channel) = channels.get(&id) else {
            return Vec::new();
        };
        if !channel
            .pending_delete
            .as_ref()
            .is_some_and(|pending| pending.nonce == nonce)
        {
            return Vec::new();
        }
        collect_subtree(&channels, id)
            .into_iter()
            .filter(|channel_id| {
                channels
                    .get(channel_id)
                    .and_then(|ch| ch.pending_delete.as_ref())
                    .is_some_and(|pending| pending.nonce == nonce)
            })
            .collect()
    }

    /// Return root pending-delete markers that have exceeded `timeout_ms`.
    pub async fn expired_pending_deletes(&self, timeout_ms: i64) -> Vec<(u32, u64)> {
        self.expired_pending_deletes_in_server(DEFAULT_SERVER_ID, timeout_ms)
            .await
    }

    pub async fn expired_pending_deletes_in_server(
        &self,
        server_id: &str,
        timeout_ms: i64,
    ) -> Vec<(u32, u64)> {
        if timeout_ms <= 0 {
            return Vec::new();
        }
        let now = chrono::Utc::now().timestamp_millis();
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return Vec::new();
        };
        let mut expired = Vec::new();
        for channel in channels.values() {
            let Some(pending) = channel.pending_delete.as_ref() else {
                continue;
            };
            if now.saturating_sub(pending.started_at_ms) < timeout_ms {
                continue;
            }
            let parent_pending_same_nonce = channel
                .parent_id
                .and_then(|parent_id| channels.get(&parent_id))
                .and_then(|parent| parent.pending_delete.as_ref())
                .is_some_and(|parent_pending| parent_pending.nonce == pending.nonce);
            if !parent_pending_same_nonce {
                expired.push((channel.id, pending.nonce));
            }
        }
        expired
    }

    pub async fn pending_delete_subtree_set_in_server(
        &self,
        server_id: &str,
        id: u32,
        nonce: u64,
    ) -> std::collections::HashSet<u32> {
        self.pending_delete_subtree_in_server(server_id, id, nonce)
            .await
            .into_iter()
            .collect()
    }

    pub async fn move_local_clients_out_of_missing_channels_in_server(
        &self,
        server_id: &str,
        valid_channel_ids: &HashSet<u32>,
        channel_version: u64,
    ) -> usize {
        let observer = { self.observer.lock().clone() };
        let Some(observer) = observer else {
            return 0;
        };
        observer
            .repair_missing_channels(server_id, valid_channel_ids, channel_version)
            .await
    }

    pub async fn get_all(&self) -> Vec<Channel> {
        self.get_all_in_server(DEFAULT_SERVER_ID).await
    }

    pub async fn get_all_in_server(&self, server_id: &str) -> Vec<Channel> {
        let channels = self.channels.read();
        match channels.get(server_id) {
            Some(channels) => {
                let mut channels: Vec<Channel> = channels.values().cloned().collect();
                if !channels.iter().any(|channel| channel.id == 0) {
                    channels.push(self.root_channel());
                }
                channels
            }
            None => vec![self.root_channel()],
        }
    }

    pub fn snapshot_with_version_and_subscription_in_server(
        &self,
        server_id: &str,
    ) -> (Vec<Channel>, u64, ChannelStateSubscription) {
        let channels = self.channels.read();
        let version = self.versions.read().get(server_id).copied().unwrap_or(0);
        let rx = self.tx.subscribe();
        let channels = match channels.get(server_id) {
            Some(channels) => {
                let mut channels: Vec<Channel> = channels.values().cloned().collect();
                if !channels.iter().any(|channel| channel.id == 0) {
                    channels.push(self.root_channel());
                }
                channels
            }
            None => vec![self.root_channel()],
        };
        (channels, version, rx)
    }

    /// Return the total number of channels.
    pub async fn len(&self) -> usize {
        self.len_in_server(DEFAULT_SERVER_ID).await
    }

    pub async fn len_in_server(&self, server_id: &str) -> usize {
        self.channels
            .read()
            .get(server_id)
            .map(|channels| channels.len().max(1))
            .unwrap_or(1)
    }

    pub async fn get_children(&self, parent_id: u32) -> Vec<Channel> {
        self.get_children_in_server(DEFAULT_SERVER_ID, parent_id)
            .await
    }

    pub async fn get_children_in_server(&self, server_id: &str, parent_id: u32) -> Vec<Channel> {
        self.channels
            .read()
            .get(server_id)
            .map(|channels| {
                channels
                    .values()
                    .filter(|c| c.parent_id == Some(parent_id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn get_all_scoped(&self) -> Vec<(String, Channel)> {
        self.channels
            .read()
            .iter()
            .flat_map(|(server_id, channels)| {
                channels
                    .values()
                    .cloned()
                    .map(|channel| (server_id.clone(), channel))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn known_server_ids(&self) -> Vec<String> {
        self.channels.read().keys().cloned().collect()
    }

    /// Returns the chain of ancestors for `channel_id`, starting from the
    /// immediate parent up to (and including) the root.
    pub async fn get_ancestors(&self, channel_id: u32) -> Vec<Channel> {
        self.get_ancestors_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn get_ancestors_in_server(&self, server_id: &str, channel_id: u32) -> Vec<Channel> {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return Vec::new();
        };
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
    pub async fn get_channel_with_ancestors(
        &self,
        channel_id: u32,
    ) -> (Option<Channel>, Vec<Channel>) {
        self.get_channel_with_ancestors_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn get_channel_with_ancestors_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> (Option<Channel>, Vec<Channel>) {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return if channel_id == 0 {
                (Some(self.root_channel()), Vec::new())
            } else {
                (None, Vec::new())
            };
        };
        let channel = channels
            .get(&channel_id)
            .cloned()
            .or_else(|| (channel_id == 0).then(|| self.root_channel()));
        let mut ancestors = Vec::new();
        let mut current_id = channel_id;
        loop {
            let Some(ch) = channels
                .get(&current_id)
                .cloned()
                .or_else(|| (current_id == 0).then(|| self.root_channel()))
            else {
                break;
            };
            let Some(pid) = ch.parent_id else { break };
            let Some(parent) = channels
                .get(&pid)
                .cloned()
                .or_else(|| (pid == 0).then(|| self.root_channel()))
            else {
                break;
            };
            ancestors.push(parent);
            current_id = pid;
        }
        (channel, ancestors)
    }

    /// Return a channel and ancestors from a stable ACL generation snapshot.
    pub async fn get_channel_with_ancestors_for_acl(
        &self,
        channel_id: u32,
    ) -> (u64, Option<Channel>, Vec<Channel>) {
        self.get_channel_with_ancestors_for_acl_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn get_channel_with_ancestors_for_acl_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> (u64, Option<Channel>, Vec<Channel>) {
        loop {
            let generation = self.channel_acl_generation_for_channel(server_id, channel_id);
            let (channel, ancestors) = self
                .get_channel_with_ancestors_in_server(server_id, channel_id)
                .await;
            if self.channel_acl_generation_for_channel(server_id, channel_id) == generation {
                return (generation, channel, ancestors);
            }
        }
    }

    // ── Mutation API ──────────────────────────────────────────────────────

    /// Allocate a fresh channel ID.  Temporary channels get bit-31 set.
    pub async fn next_channel_id(&self, temporary: bool) -> u32 {
        self.next_channel_id_in_server(DEFAULT_SERVER_ID, temporary)
            .await
    }

    pub async fn next_channel_id_in_server(&self, server_id: &str, temporary: bool) -> u32 {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return if temporary {
                TEMPORARY_CHANNEL_ID_BIT | 1
            } else {
                1
            };
        };
        next_available_channel_id(channels, temporary)
    }

    pub async fn create_channel(
        self: &Arc<Self>,
        channel: Channel,
    ) -> Result<Channel, ChannelRepoError> {
        self.create_channel_in_server(DEFAULT_SERVER_ID, channel)
            .await
    }

    pub async fn create_channel_in_server(
        self: &Arc<Self>,
        server_id: &str,
        mut channel: Channel,
    ) -> Result<Channel, ChannelRepoError> {
        let op = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);

            // Validate parent exists
            if let Some(pid) = channel.parent_id {
                if !channels.contains_key(&pid) && pid != 0 {
                    return Err(ChannelRepoError::ParentNotFound(pid));
                }
                if channels
                    .get(&pid)
                    .is_some_and(|parent| parent.is_temporary())
                {
                    return Err(ChannelRepoError::TemporaryChannelCannotHaveChildren(pid));
                }
            }

            if channels.contains_key(&channel.id) {
                channel.id = next_available_channel_id(channels, channel.is_temporary());
            }

            validate_new_channel_links(channels, &channel)?;

            // Validate name uniqueness within parent
            if channels.values().any(|c| {
                c.parent_id == channel.parent_id && c.name == channel.name && c.id != channel.id
            }) {
                return Err(ChannelRepoError::NameConflict(channel.name.clone()));
            }

            let op = self.make_op_in_server(
                server_id,
                ChannelOp::CreateChannel {
                    channel: channel.clone(),
                },
            );
            channels.insert(channel.id, channel.clone());
            if !channel.links.is_empty() {
                let mut link_topologies = self.link_topologies.write();
                sync_link_topology_for_server(&mut link_topologies, server_id, channels);
            }
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
        self.update_channel_in_server(DEFAULT_SERVER_ID, id, patch)
            .await
    }

    pub async fn update_channel_in_server(
        self: &Arc<Self>,
        server_id: &str,
        id: u32,
        patch: ChannelPatch,
    ) -> Result<Channel, ChannelRepoError> {
        let parent_changed = patch.parent_id.is_some();
        let patch = self.normalize_patch_for_channel(id, patch);
        let (op, updated) = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);

            if !channels.contains_key(&id) {
                return Err(ChannelRepoError::NotFound(id));
            }

            // Validate new parent, if changing
            if let Some(new_parent) = patch.parent_id {
                if let Some(pid) = new_parent {
                    if !channels.contains_key(&pid) {
                        return Err(ChannelRepoError::ParentNotFound(pid));
                    }
                    if channels
                        .get(&pid)
                        .is_some_and(|parent| parent.is_temporary())
                    {
                        return Err(ChannelRepoError::TemporaryChannelCannotHaveChildren(pid));
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

            let op = self.make_op_in_server(
                server_id,
                ChannelOp::UpdateChannel {
                    id,
                    patch: patch.clone(),
                },
            );
            apply_patch(channels.get_mut(&id).unwrap(), &patch);
            let updated = channels[&id].clone();
            (op, updated)
        };

        if parent_changed {
            self.invalidate_acl_cache_for_op_in_server(server_id, &op.op)
                .await;
        }
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
        self.edit_channel_in_server(DEFAULT_SERVER_ID, id, patch, links_add, links_remove)
            .await
    }

    pub async fn edit_channel_in_server(
        self: &Arc<Self>,
        server_id: &str,
        id: u32,
        patch: ChannelPatch,
        links_add: Vec<u32>,
        links_remove: Vec<u32>,
    ) -> Result<Channel, ChannelRepoError> {
        let parent_changed = patch.parent_id.is_some();
        let patch = self.normalize_patch_for_channel(id, patch);
        let links_changed = !links_add.is_empty() || !links_remove.is_empty();
        let updated = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);

            if !channels.contains_key(&id) {
                return Err(ChannelRepoError::NotFound(id));
            }

            if let Some(new_parent) = patch.parent_id {
                if let Some(pid) = new_parent {
                    if !channels.contains_key(&pid) {
                        return Err(ChannelRepoError::ParentNotFound(pid));
                    }
                    if channels
                        .get(&pid)
                        .is_some_and(|parent| parent.is_temporary())
                    {
                        return Err(ChannelRepoError::TemporaryChannelCannotHaveChildren(pid));
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

            if !links_add.is_empty() && channels[&id].is_temporary() {
                return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(id));
            }
            for &link_add in &links_add {
                if link_add == id {
                    continue;
                }
                if !channels.contains_key(&link_add) {
                    return Err(ChannelRepoError::NotFound(link_add));
                }
                if channels[&link_add].is_temporary() {
                    return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(link_add));
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
            if links_changed {
                let mut link_topologies = self.link_topologies.write();
                sync_link_topology_for_server(&mut link_topologies, server_id, channels);
            }
            channels[&id].clone()
        };

        let op = self.make_op_in_server(
            server_id,
            ChannelOp::EditChannel {
                id,
                patch,
                links_add,
                links_remove,
            },
        );
        if parent_changed {
            self.invalidate_acl_cache_for_op_in_server(server_id, &op.op)
                .await;
        }
        self.commit(op).await?;
        Ok(updated)
    }

    /// Delete a channel and all its descendants.  Users should be moved to
    /// the parent by the caller before invoking this.
    pub async fn delete_channel(self: &Arc<Self>, id: u32) -> Result<Vec<u32>, ChannelRepoError> {
        self.delete_channel_in_server(DEFAULT_SERVER_ID, id).await
    }

    pub async fn delete_channel_in_server(
        self: &Arc<Self>,
        server_id: &str,
        id: u32,
    ) -> Result<Vec<u32>, ChannelRepoError> {
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }

        let nonce = rand::random::<u64>();
        let to_delete = self
            .mark_pending_delete_in_server(server_id, id, nonce)
            .await?;
        self.apply_delete_channel_in_server(server_id, id, nonce)
            .await?;
        Ok(to_delete)
    }

    /// Mark a channel subtree as pending deletion using a nonce shared by the
    /// later delete operation. Returns the subtree ids that were marked.
    pub async fn mark_pending_delete(
        self: &Arc<Self>,
        id: u32,
        nonce: u64,
    ) -> Result<Vec<u32>, ChannelRepoError> {
        self.mark_pending_delete_in_server(DEFAULT_SERVER_ID, id, nonce)
            .await
    }

    pub async fn mark_pending_delete_in_server(
        self: &Arc<Self>,
        server_id: &str,
        id: u32,
        nonce: u64,
    ) -> Result<Vec<u32>, ChannelRepoError> {
        self.mark_pending_delete_in_server_with_evict_clients(server_id, id, nonce, true)
            .await
    }

    pub async fn mark_pending_delete_in_server_with_evict_clients(
        self: &Arc<Self>,
        server_id: &str,
        id: u32,
        nonce: u64,
        evict_clients: bool,
    ) -> Result<Vec<u32>, ChannelRepoError> {
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }
        let to_delete = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            if !channels.contains_key(&id) {
                return Err(ChannelRepoError::NotFound(id));
            }
            let to_delete = collect_subtree(&channels, id);
            let started_at_ms = chrono::Utc::now().timestamp_millis();
            for del_id in &to_delete {
                if let Some(ch) = channels.get_mut(del_id) {
                    ch.pending_delete = Some(PendingDeleteState {
                        nonce,
                        started_at_ms,
                        origin_node: self.node_id,
                    });
                }
            }
            to_delete
        };
        let op = self.make_op_in_server(
            server_id,
            ChannelOp::MarkPendingDelete {
                id,
                nonce,
                evict_clients,
            },
        );
        self.commit(op).await?;
        Ok(to_delete)
    }

    /// Apply a nonce-bearing delete. If the pending nonce no longer matches,
    /// the operation is committed as a semantic no-op and emits no ChannelRemove.
    pub async fn apply_delete_channel(
        self: &Arc<Self>,
        id: u32,
        nonce: u64,
    ) -> Result<bool, ChannelRepoError> {
        self.apply_delete_channel_in_server(DEFAULT_SERVER_ID, id, nonce)
            .await
    }

    pub async fn apply_delete_channel_in_server(
        self: &Arc<Self>,
        server_id: &str,
        id: u32,
        nonce: u64,
    ) -> Result<bool, ChannelRepoError> {
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }
        let applied_delete = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            if !channels.contains_key(&id) {
                return Err(ChannelRepoError::NotFound(id));
            };
            let applied_delete = apply_delete_channel_to_map(channels, id, nonce);
            if let Some(applied_delete) = &applied_delete {
                apply_link_topology_effect(
                    &self.link_topologies,
                    server_id,
                    channels,
                    applied_delete.link_topology_effect.clone(),
                );
            }
            applied_delete
        };
        let mut op = self.make_op_in_server(server_id, ChannelOp::DeleteChannel { id, nonce });
        op.emits_client_message = applied_delete.is_some();
        if let Some(applied_delete) = &applied_delete {
            self.invalidate_acl_cache_for_op_scope(
                server_id,
                applied_delete.deleted_ids.iter().copied().collect(),
            );
        }
        let deleted = op.emits_client_message;
        self.commit_with_delete_visibility_hint(
            op,
            applied_delete.map(|applied_delete| applied_delete.deleted_ids),
        )
        .await?;
        Ok(deleted)
    }

    /// Cancel a pending delete if the nonce still matches.
    pub async fn cancel_pending_delete(
        self: &Arc<Self>,
        id: u32,
        nonce: u64,
    ) -> Result<(), ChannelRepoError> {
        self.cancel_pending_delete_in_server(DEFAULT_SERVER_ID, id, nonce)
            .await
    }

    pub async fn cancel_pending_delete_in_server(
        self: &Arc<Self>,
        server_id: &str,
        id: u32,
        nonce: u64,
    ) -> Result<(), ChannelRepoError> {
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }
        {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            let to_cancel = collect_subtree(&channels, id);
            for cancel_id in &to_cancel {
                if let Some(ch) = channels.get_mut(cancel_id) {
                    if ch
                        .pending_delete
                        .as_ref()
                        .is_some_and(|pending| pending.nonce == nonce)
                    {
                        ch.pending_delete = None;
                    }
                }
            }
        }
        let op = self.make_op_in_server(server_id, ChannelOp::CancelPendingDelete { id, nonce });
        self.commit(op).await?;
        Ok(())
    }

    pub async fn add_link(self: &Arc<Self>, a: u32, b: u32) -> Result<(), ChannelRepoError> {
        self.add_link_in_server(DEFAULT_SERVER_ID, a, b).await
    }

    pub async fn add_link_in_server(
        self: &Arc<Self>,
        server_id: &str,
        a: u32,
        b: u32,
    ) -> Result<(), ChannelRepoError> {
        if a == b {
            return Ok(()); // no-op; callers should reject same-channel links
        }
        {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            if !channels.contains_key(&a) {
                return Err(ChannelRepoError::NotFound(a));
            }
            if !channels.contains_key(&b) {
                return Err(ChannelRepoError::NotFound(b));
            }
            if channels[&a].is_temporary() {
                return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(a));
            }
            if channels[&b].is_temporary() {
                return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(b));
            }
            channels.get_mut(&a).unwrap().links.insert(b);
            channels.get_mut(&b).unwrap().links.insert(a);
            let mut link_topologies = self.link_topologies.write();
            sync_link_topology_for_server(&mut link_topologies, server_id, channels);
        }

        let op = self.make_op_in_server(server_id, ChannelOp::AddLink { a, b });
        self.commit(op).await?;
        Ok(())
    }

    pub async fn remove_link(self: &Arc<Self>, a: u32, b: u32) -> Result<(), ChannelRepoError> {
        self.remove_link_in_server(DEFAULT_SERVER_ID, a, b).await
    }

    pub async fn remove_link_in_server(
        self: &Arc<Self>,
        server_id: &str,
        a: u32,
        b: u32,
    ) -> Result<(), ChannelRepoError> {
        {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            if let Some(ch) = channels.get_mut(&a) {
                ch.links.remove(&b);
            }
            if let Some(ch) = channels.get_mut(&b) {
                ch.links.remove(&a);
            }
            let mut link_topologies = self.link_topologies.write();
            sync_link_topology_for_server(&mut link_topologies, server_id, channels);
        }

        let op = self.make_op_in_server(server_id, ChannelOp::RemoveLink { a, b });
        self.commit(op).await?;
        Ok(())
    }

    pub async fn set_acls(
        self: &Arc<Self>,
        channel_id: u32,
        inherit_acl: bool,
        acls: Vec<ACL>,
    ) -> Result<(), ChannelRepoError> {
        self.set_acls_in_server(DEFAULT_SERVER_ID, channel_id, inherit_acl, acls)
            .await
    }

    pub async fn set_acls_in_server(
        self: &Arc<Self>,
        server_id: &str,
        channel_id: u32,
        inherit_acl: bool,
        acls: Vec<ACL>,
    ) -> Result<(), ChannelRepoError> {
        {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            let ch = channels
                .get_mut(&channel_id)
                .ok_or(ChannelRepoError::NotFound(channel_id))?;
            ch.inherit_acl = inherit_acl;
            ch.acls = acls.clone();
        }

        let op = self.make_op_in_server(
            server_id,
            ChannelOp::SetAcls {
                channel_id,
                inherit_acl,
                acls,
            },
        );
        self.invalidate_acl_cache_for_op_in_server(server_id, &op.op)
            .await;
        self.commit(op).await?;
        Ok(())
    }

    // ── ACL cache ─────────────────────────────────────────────────────────

    pub async fn get_cached_permissions(
        &self,
        session_id: u64,
        client_instance_id: u64,
        channel_id: u32,
        channel_acl_generation: u64,
        client_acl_generation: u64,
    ) -> Option<BitFlags<ACLPermissions>> {
        self.get_cached_permissions_in_server(
            DEFAULT_SERVER_ID,
            session_id,
            client_instance_id,
            channel_id,
            channel_acl_generation,
            client_acl_generation,
            false,
        )
        .await
    }

    pub async fn get_cached_permissions_in_server(
        &self,
        server_id: &str,
        session_id: u64,
        client_instance_id: u64,
        channel_id: u32,
        channel_acl_generation: u64,
        client_acl_generation: u64,
        explicit_enter_deny_overrides_write: bool,
    ) -> Option<BitFlags<ACLPermissions>> {
        self.acl_cache
            .get_sync(&(
                server_id.to_owned(),
                session_id,
                client_instance_id,
                channel_id,
            ))
            .and_then(|entry| {
                let cache_key_matches = entry.channel_acl_generation == channel_acl_generation
                    && entry.client_acl_generation == client_acl_generation
                    && entry.explicit_enter_deny_overrides_write
                        == explicit_enter_deny_overrides_write;
                cache_key_matches.then_some(entry.permissions)
            })
    }

    pub async fn cache_permissions(
        &self,
        session_id: u64,
        client_instance_id: u64,
        channel_id: u32,
        channel_acl_generation: u64,
        client_acl_generation: u64,
        permissions: BitFlags<ACLPermissions>,
    ) {
        self.cache_permissions_in_server(
            DEFAULT_SERVER_ID,
            session_id,
            client_instance_id,
            channel_id,
            channel_acl_generation,
            client_acl_generation,
            false,
            permissions,
        )
        .await;
    }

    pub async fn cache_permissions_in_server(
        &self,
        server_id: &str,
        session_id: u64,
        client_instance_id: u64,
        channel_id: u32,
        channel_acl_generation: u64,
        client_acl_generation: u64,
        explicit_enter_deny_overrides_write: bool,
        permissions: BitFlags<ACLPermissions>,
    ) {
        let key = (
            server_id.to_owned(),
            session_id,
            client_instance_id,
            channel_id,
        );
        let _ = self
            .acl_cache
            .entry_sync(key)
            .put_entry(CachedAclPermissions {
                channel_acl_generation,
                client_acl_generation,
                explicit_enter_deny_overrides_write,
                permissions,
            });
    }

    pub async fn invalidate_acl_cache_for_channel(&self, channel_id: u32) {
        self.invalidate_acl_cache_for_channel_in_server(DEFAULT_SERVER_ID, channel_id)
            .await;
    }

    pub async fn invalidate_acl_cache_for_channel_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) {
        let channel_ids = HashSet::from([channel_id]);
        self.invalidate_acl_cache_for_channels(server_id, &channel_ids);
    }

    pub async fn invalidate_all_acl_cache(&self) {
        self.invalidate_all_acl_cache_sync();
    }

    fn invalidate_all_acl_cache_sync(&self) {
        self.bump_channel_acl_generation();
        self.acl_cache.clear_sync();
    }

    fn invalidate_acl_cache_for_channels(&self, server_id: &str, channel_ids: &HashSet<u32>) {
        if channel_ids.is_empty() {
            return;
        }
        self.bump_channel_acl_generation_for_channels(server_id, channel_ids);
        self.acl_cache.retain_sync(|key, _| {
            let (entry_server_id, _, _, entry_channel_id) = key;
            entry_server_id != server_id || !channel_ids.contains(entry_channel_id)
        });
    }

    fn invalidate_acl_cache_for_op_scope(&self, server_id: &str, channel_ids: HashSet<u32>) {
        self.invalidate_acl_cache_for_channels(server_id, &channel_ids);
    }

    async fn invalidate_acl_cache_for_op_in_server(&self, server_id: &str, op: &ChannelOp) {
        if let Some(channel_ids) = self.acl_affected_channel_ids_for_op(server_id, op).await {
            self.invalidate_acl_cache_for_op_scope(server_id, channel_ids);
        }
    }

    pub async fn invalidate_acl_cache_for_user(&self, _session_id: u64) {}

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

        let versions = self.versions.read().clone();
        let history_freshness = self.history_freshness.read().clone();
        let version = versions.get(DEFAULT_SERVER_ID).copied().unwrap_or_default();
        let channels: Vec<SnapshotChannel> = self
            .channels
            .read()
            .iter()
            .flat_map(|(server_id, channels)| {
                channels
                    .values()
                    .cloned()
                    .map(|channel| SnapshotChannel {
                        server_id: server_id.clone(),
                        channel: ChannelSnapshotState::from_channel(&channel),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let snap = Snapshot {
            version,
            versions,
            history_freshness,
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

                let src = tokio::fs::OpenOptions::new()
                    .read(true)
                    .open(&wal_path)
                    .await?;
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
        self.get_log_entries_since(DEFAULT_SERVER_ID, since_version)
            .await
            .into_iter()
            .map(|entry| entry.op())
            .collect()
    }

    pub async fn get_log_entries_since(
        &self,
        server_id: &str,
        since_version: u64,
    ) -> Vec<ChannelLogEntry> {
        self.get_log_entries_since_in_server(server_id, since_version)
            .await
    }

    pub async fn get_log_since_in_server(
        &self,
        server_id: &str,
        since_version: u64,
    ) -> Vec<Arc<ChannelOperation>> {
        self.get_log_entries_since_in_server(server_id, since_version)
            .await
            .into_iter()
            .map(|entry| entry.op())
            .collect()
    }

    pub async fn get_log_entries_since_in_server(
        &self,
        server_id: &str,
        since_version: u64,
    ) -> Vec<ChannelLogEntry> {
        self.log
            .read()
            .iter()
            .filter(|entry| entry.op.server_id == server_id && entry.op.version > since_version)
            .cloned()
            .collect()
    }

    pub async fn acl_affected_channel_ids_for_op(
        &self,
        server_id: &str,
        op: &ChannelOp,
    ) -> Option<HashSet<u32>> {
        let channels = self.channels.read();
        let channels = channels.get(server_id)?;
        Some(acl_affected_channel_ids_for_op_in_map(channels, op)?)
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
        if op.version <= self.current_version_in_server(&op.server_id) {
            return Ok(());
        }
        let (new_version, affected_acl_channels) = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(op.server_id.clone()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            let normalized_op = normalize_op_for_root(&op.op, &root_config);
            let mut should_invalidate_acl = channel_op_invalidates_acl_cache(&normalized_op);
            let mut deleted_subtree = None;
            let link_topology_effect = match &normalized_op {
                ChannelOp::DeleteChannel { id, nonce } => {
                    let applied_delete = apply_delete_channel_to_map(channels, *id, *nonce);
                    should_invalidate_acl = applied_delete.is_some();
                    if let Some(applied_delete) = applied_delete {
                        deleted_subtree =
                            Some(applied_delete.deleted_ids.iter().copied().collect());
                        applied_delete.link_topology_effect
                    } else {
                        LinkTopologyEffect::Unchanged
                    }
                }
                _ => {
                    apply_op_to_map(channels, &normalized_op, op.node_id, &root_config);
                    if channel_op_affects_link_topology(&normalized_op) {
                        LinkTopologyEffect::Rebuild
                    } else {
                        LinkTopologyEffect::Unchanged
                    }
                }
            };
            apply_link_topology_effect(
                &self.link_topologies,
                &op.server_id,
                channels,
                link_topology_effect,
            );
            let affected_acl_channels = if deleted_subtree.is_some() {
                deleted_subtree
            } else {
                should_invalidate_acl
                    .then(|| acl_affected_channel_ids_for_op_in_map(channels, &normalized_op))
                    .flatten()
            };
            let new_version = op.version;
            self.versions
                .write()
                .entry(op.server_id.clone())
                .and_modify(|version| *version = (*version).max(new_version))
                .or_insert(new_version);
            (new_version, affected_acl_channels)
        };

        if let Some(affected_acl_channels) = affected_acl_channels {
            self.invalidate_acl_cache_for_op_scope(&op.server_id, affected_acl_channels);
        }

        let observer = { self.observer.lock().clone() };
        if let Some(observer) = observer {
            observer
                .channel_version_advanced(&op.server_id, new_version)
                .await;
        }

        Ok(())
    }

    /// Apply an already-versioned operation and persist it through the
    /// repository's native WAL/snapshot pipeline.
    pub async fn apply_committed_operation(
        self: &Arc<Self>,
        op: ChannelOperation,
    ) -> Result<Arc<ChannelOperation>, ChannelRepoError> {
        self.apply_committed_operation_with_metadata(op, None).await
    }

    pub async fn apply_committed_operation_with_metadata(
        self: &Arc<Self>,
        mut op: ChannelOperation,
        strict_metadata: Option<StrictReplicationMetadata>,
    ) -> Result<Arc<ChannelOperation>, ChannelRepoError> {
        if op.server_id.is_empty() {
            op.server_id = default_server_id();
        }
        if op.version <= self.current_version_in_server(&op.server_id) {
            return Ok(Arc::new(op));
        }

        let mut should_invalidate_acl = channel_op_invalidates_acl_cache(&op.op);
        let server_id = op.server_id.clone();
        let mut deleted_channel_hint = None;
        let (evicting_pending_delete, affected_acl_channels) = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.clone()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            op.op = normalize_op_for_root(&op.op, &root_config);
            let mut deleted_subtree = None;
            let evicting_pending_delete = match &op.op {
                ChannelOp::MarkPendingDelete {
                    id,
                    nonce,
                    evict_clients,
                } if *evict_clients => channels.get(id).map(|channel| {
                    let _ = channel;
                    (*id, *nonce)
                }),
                ChannelOp::DeleteChannel { .. } => None,
                _ => None,
            };
            let link_topology_effect = match &op.op {
                ChannelOp::DeleteChannel { id, nonce } => {
                    let applied_delete = apply_delete_channel_to_map(channels, *id, *nonce);
                    op.emits_client_message = applied_delete.is_some();
                    should_invalidate_acl = applied_delete.is_some();
                    if let Some(applied_delete) = applied_delete {
                        deleted_channel_hint = Some(applied_delete.deleted_ids.clone());
                        deleted_subtree =
                            Some(applied_delete.deleted_ids.iter().copied().collect());
                        applied_delete.link_topology_effect
                    } else {
                        LinkTopologyEffect::Unchanged
                    }
                }
                _ => {
                    apply_op_to_map(channels, &op.op, op.node_id, &root_config);
                    if channel_op_affects_link_topology(&op.op) {
                        LinkTopologyEffect::Rebuild
                    } else {
                        LinkTopologyEffect::Unchanged
                    }
                }
            };
            apply_link_topology_effect(
                &self.link_topologies,
                &server_id,
                channels,
                link_topology_effect,
            );
            let affected_acl_channels = if deleted_subtree.is_some() {
                deleted_subtree
            } else {
                should_invalidate_acl
                    .then(|| acl_affected_channel_ids_for_op_in_map(channels, &op.op))
                    .flatten()
            };
            (evicting_pending_delete, affected_acl_channels)
        };

        if let Some(affected_acl_channels) = affected_acl_channels {
            self.invalidate_acl_cache_for_op_scope(&server_id, affected_acl_channels);
        }
        let committed = self
            .commit_assigned_operation(op, strict_metadata, deleted_channel_hint)
            .await?;

        if let Some((id, nonce)) = evicting_pending_delete {
            let subtree = self
                .pending_delete_subtree_set_in_server(&server_id, id, nonce)
                .await;
            if !subtree.is_empty() {
                tracing::trace!(
                    channel_id = id,
                    nonce,
                    subtree_len = subtree.len(),
                    "replicated pending-delete subtree is ready for caller-side local client eviction"
                );
            }
        }

        Ok(committed)
    }

    pub async fn install_s2s_snapshot(
        self: &Arc<Self>,
        version: u64,
        channels_snapshot: Vec<Channel>,
    ) -> Result<(), ChannelRepoError> {
        self.install_s2s_snapshot_in_server(
            DEFAULT_SERVER_ID,
            version,
            channels_snapshot,
            chrono::Utc::now().timestamp(),
        )
        .await
    }

    pub async fn install_s2s_snapshot_in_server(
        self: &Arc<Self>,
        server_id: &str,
        version: u64,
        channels_snapshot: Vec<Channel>,
        freshness: i64,
    ) -> Result<(), ChannelRepoError> {
        let (valid_channel_ids, notification_channels, removed_channel_ids) = {
            let mut ids = HashSet::new();
            let mut notification_channels = Vec::new();
            let mut removed_channel_ids = Vec::new();
            {
                let mut all_channels = self.channels.write();
                let channels = all_channels.entry(server_id.to_owned()).or_default();
                let root_config = self.root_config.read().clone();
                let old_ids: HashSet<u32> = channels.keys().copied().collect();
                channels.clear();
                for mut channel in channels_snapshot {
                    if channel.id == 0 {
                        channel.name = root_config.name().to_owned();
                    }
                    channels.insert(channel.id, channel);
                }
                ensure_root_channel(channels, &root_config);
                let mut link_topologies = self.link_topologies.write();
                sync_link_topology_for_server(&mut link_topologies, server_id, channels);
                ids.extend(channels.keys().copied());
                notification_channels.extend(channels.values().cloned());
                removed_channel_ids.extend(
                    old_ids
                        .difference(&ids)
                        .filter(|channel_id| **channel_id != 0)
                        .copied(),
                );
                self.versions.write().insert(server_id.to_owned(), version);
                self.log
                    .write()
                    .retain(|entry| entry.op.server_id != server_id);
            }
            (ids, notification_channels, removed_channel_ids)
        };
        self.history_freshness
            .write()
            .insert(server_id.to_owned(), freshness);
        self.channel_acl_generation.fetch_add(1, Ordering::AcqRel);
        self.acl_cache.clear_sync();

        let _ = self.tx.send(Arc::new(ChannelOperation {
            server_id: server_id.to_owned(),
            version,
            node_id: self.node_id,
            timestamp: freshness,
            emits_client_message: true,
            op: ChannelOp::InstallSnapshot {
                channels: notification_channels,
                removed: removed_channel_ids,
            },
        }));

        let observer = { self.observer.lock().clone() };
        if let Some(observer) = observer {
            observer.channel_version_advanced(server_id, version).await;
        }
        let repaired = self
            .move_local_clients_out_of_missing_channels_in_server(
                server_id,
                &valid_channel_ids,
                version,
            )
            .await;
        if repaired > 0 {
            tracing::trace!(
                server_id,
                repaired,
                "repaired local clients after s2s channel snapshot install"
            );
        }

        if self.storage_dir.is_some() {
            if let Err(e) = self.save_snapshot().await {
                tracing::warn!("channel snapshot compaction failed after s2s install: {e}");
            }
        }

        Ok(())
    }

    pub fn set_observer(&self, observer: Arc<dyn ChannelRepositoryObserver>) {
        *self.observer.lock() = Some(observer);
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn make_op_in_server(&self, server_id: &str, op: ChannelOp) -> ChannelOperation {
        let root_config = self.root_config.read().clone();
        ChannelOperation {
            server_id: server_id.to_owned(),
            version: 0, // assigned by commit()
            node_id: self.node_id,
            timestamp: chrono::Utc::now().timestamp(),
            emits_client_message: true,
            op: normalize_op_for_root(&op, &root_config),
        }
    }

    pub async fn validate_s2s_op(&self, op: &ChannelOp) -> Result<(), ChannelRepoError> {
        self.validate_s2s_op_in_server(DEFAULT_SERVER_ID, op).await
    }

    pub async fn validate_s2s_op_in_server(
        &self,
        server_id: &str,
        op: &ChannelOp,
    ) -> Result<(), ChannelRepoError> {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return Ok(());
        };
        let root_config = self.root_config.read().clone();
        let op = normalize_op_for_root(op, &root_config);
        match &op {
            ChannelOp::CreateChannel { channel } => {
                if let Some(pid) = channel.parent_id {
                    if !channels.contains_key(&pid) && pid != 0 {
                        return Err(ChannelRepoError::ParentNotFound(pid));
                    }
                    if channels
                        .get(&pid)
                        .is_some_and(|parent| parent.is_temporary())
                    {
                        return Err(ChannelRepoError::TemporaryChannelCannotHaveChildren(pid));
                    }
                }
                validate_new_channel_links(channels, channel)?;
                if channels.values().any(|c| {
                    c.parent_id == channel.parent_id && c.name == channel.name && c.id != channel.id
                }) {
                    return Err(ChannelRepoError::NameConflict(channel.name.clone()));
                }
            }
            ChannelOp::UpdateChannel { id, patch } | ChannelOp::EditChannel { id, patch, .. } => {
                if !channels.contains_key(id) {
                    return Err(ChannelRepoError::NotFound(*id));
                }
                if let Some(new_parent) = patch.parent_id {
                    if let Some(pid) = new_parent {
                        if !channels.contains_key(&pid) {
                            return Err(ChannelRepoError::ParentNotFound(pid));
                        }
                        if channels
                            .get(&pid)
                            .is_some_and(|parent| parent.is_temporary())
                        {
                            return Err(ChannelRepoError::TemporaryChannelCannotHaveChildren(pid));
                        }
                        if is_descendant(&channels, pid, *id) {
                            return Err(ChannelRepoError::CannotMoveIntoDescendant);
                        }
                    }
                }
                if let Some(ref new_name) = patch.name {
                    let target_parent = patch.parent_id.unwrap_or_else(|| channels[id].parent_id);
                    if channels
                        .values()
                        .any(|c| c.parent_id == target_parent && &c.name == new_name && c.id != *id)
                    {
                        return Err(ChannelRepoError::NameConflict(new_name.clone()));
                    }
                }
                if let ChannelOp::EditChannel { links_add, .. } = &op {
                    if !links_add.is_empty() && channels[id].is_temporary() {
                        return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(*id));
                    }
                    for &link_add in links_add {
                        if link_add != *id && !channels.contains_key(&link_add) {
                            return Err(ChannelRepoError::NotFound(link_add));
                        }
                        if link_add != *id && channels[&link_add].is_temporary() {
                            return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(link_add));
                        }
                    }
                }
            }
            ChannelOp::MarkPendingDelete { id, .. } => {
                if *id == 0 {
                    return Err(ChannelRepoError::CannotDeleteRoot);
                }
                if !channels.contains_key(id) {
                    return Err(ChannelRepoError::NotFound(*id));
                }
            }
            ChannelOp::DeleteChannel { id, .. } => {
                if *id == 0 {
                    return Err(ChannelRepoError::CannotDeleteRoot);
                }
                if !channels.contains_key(id) {
                    return Err(ChannelRepoError::NotFound(*id));
                }
            }
            ChannelOp::CancelPendingDelete { id, .. } => {
                if *id == 0 {
                    return Err(ChannelRepoError::CannotDeleteRoot);
                }
            }
            ChannelOp::AddLink { a, b } => {
                if a == b {
                    return Ok(());
                }
                if !channels.contains_key(a) {
                    return Err(ChannelRepoError::NotFound(*a));
                }
                if !channels.contains_key(b) {
                    return Err(ChannelRepoError::NotFound(*b));
                }
                if channels[a].is_temporary() {
                    return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(*a));
                }
                if channels[b].is_temporary() {
                    return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(*b));
                }
            }
            ChannelOp::RemoveLink { .. } => {}
            ChannelOp::SetAcls { channel_id, .. } => {
                if !channels.contains_key(channel_id) {
                    return Err(ChannelRepoError::NotFound(*channel_id));
                }
            }
            ChannelOp::InstallSnapshot { .. } => {}
        }
        Ok(())
    }

    async fn commit_assigned_operation(
        &self,
        mut op: ChannelOperation,
        strict_metadata: Option<StrictReplicationMetadata>,
        deleted_channel_ids: Option<Vec<u32>>,
    ) -> Result<Arc<ChannelOperation>, ChannelRepoError> {
        let root_config = self.root_config.read().clone();
        op.op = normalize_op_for_root(&op.op, &root_config);
        let op = {
            let mut log = self.log.write();
            self.versions
                .write()
                .entry(op.server_id.clone())
                .and_modify(|version| *version = (*version).max(op.version))
                .or_insert(op.version);
            let op = Arc::new(op);
            log.push_back(ChannelLogEntry::new(Arc::clone(&op), strict_metadata));
            if let Some(mut deleted_channel_ids) = deleted_channel_ids {
                deleted_channel_ids.sort_unstable();
                deleted_channel_ids.dedup();
                self.delete_visibility_hints.write().insert(
                    (op.server_id.clone(), op.version),
                    Arc::<[u32]>::from(deleted_channel_ids.into_boxed_slice()),
                );
            }
            while log.len() > self.log_max_entries {
                if let Some(evicted) = log.pop_front() {
                    self.delete_visibility_hints
                        .write()
                        .remove(&(evicted.op.server_id.clone(), evicted.op.version));
                }
            }
            op
        };
        self.history_freshness
            .write()
            .entry(op.server_id.clone())
            .and_modify(|freshness| *freshness = (*freshness).max(op.timestamp))
            .or_insert(op.timestamp);

        if let Some(ref wal_mutex) = self.wal_file {
            let record = ChannelWalRecord::new(&op, strict_metadata);
            let mut line =
                serde_json::to_string(&record).map_err(|e| ChannelRepoError::WalCorrupt {
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
        let committed_server_id = op.server_id.clone();
        let _ = self.tx.send(Arc::clone(&op));

        let observer = { self.observer.lock().clone() };
        if let Some(observer) = observer {
            observer
                .channel_version_advanced(&committed_server_id, committed_version)
                .await;
        }

        let now = chrono::Utc::now().timestamp();
        let last_snapshot = self.last_snapshot_at.load(Ordering::Acquire);
        let ops_due = committed_version % self.snapshot_every_ops == 0;
        let time_due = now.saturating_sub(last_snapshot) >= self.snapshot_every_secs;
        if self.storage_dir.is_some() && (ops_due || time_due) {
            if let Err(e) = self.save_snapshot().await {
                tracing::warn!("channel snapshot compaction failed: {e}");
            }
        }

        Ok(op)
    }

    async fn commit(&self, mut op: ChannelOperation) -> Result<(), ChannelRepoError> {
        let root_config = self.root_config.read().clone();
        op.op = normalize_op_for_root(&op.op, &root_config);
        let version = {
            let mut versions = self.versions.write();
            let version = versions.entry(op.server_id.clone()).or_insert(0);
            *version += 1;
            *version
        };
        debug_assert!(
            version < u64::MAX - 1_000_000,
            "ChannelRepository version counter approaching u64::MAX — likely a bug"
        );
        op.version = version;
        let _ = self.commit_assigned_operation(op, None, None).await?;
        Ok(())
    }

    async fn commit_with_delete_visibility_hint(
        &self,
        mut op: ChannelOperation,
        deleted_channel_ids: Option<Vec<u32>>,
    ) -> Result<(), ChannelRepoError> {
        let root_config = self.root_config.read().clone();
        op.op = normalize_op_for_root(&op.op, &root_config);
        let version = {
            let mut versions = self.versions.write();
            let version = versions.entry(op.server_id.clone()).or_insert(0);
            *version += 1;
            *version
        };
        debug_assert!(
            version < u64::MAX - 1_000_000,
            "ChannelRepository version counter approaching u64::MAX — likely a bug"
        );
        op.version = version;
        let _ = self
            .commit_assigned_operation(op, None, deleted_channel_ids)
            .await?;
        Ok(())
    }

    fn root_channel(&self) -> Channel {
        root_channel(&self.root_config.read())
    }

    fn normalize_patch_for_channel(&self, id: u32, patch: ChannelPatch) -> ChannelPatch {
        if id == 0 {
            normalize_root_patch(patch)
        } else {
            patch
        }
    }
}

// ─── free functions used both by open() replay and by mutation methods ────────

fn next_available_channel_id(channels: &HashMap<u32, Channel>, temporary: bool) -> u32 {
    let max_non_temporary_id = channels
        .keys()
        .filter(|id| **id & TEMPORARY_CHANNEL_ID_BIT == 0)
        .max()
        .copied()
        .unwrap_or(0);
    let mut base = max_non_temporary_id
        .checked_add(1)
        .filter(|id| *id & TEMPORARY_CHANNEL_ID_BIT == 0)
        .expect("channel id space exhausted");

    loop {
        let candidate = if temporary {
            base | TEMPORARY_CHANNEL_ID_BIT
        } else {
            base
        };
        if !channels.contains_key(&candidate) {
            return candidate;
        }
        base = base
            .checked_add(1)
            .filter(|id| *id & TEMPORARY_CHANNEL_ID_BIT == 0)
            .expect("channel id space exhausted");
    }
}

fn validate_new_channel_links(
    channels: &HashMap<u32, Channel>,
    channel: &Channel,
) -> Result<(), ChannelRepoError> {
    if channel.links.is_empty() {
        return Ok(());
    }
    if channel.is_temporary() {
        return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(channel.id));
    }
    for &linked_id in &channel.links {
        if linked_id == channel.id {
            continue;
        }
        if !channels.contains_key(&linked_id) {
            return Err(ChannelRepoError::NotFound(linked_id));
        }
        if channels[&linked_id].is_temporary() {
            return Err(ChannelRepoError::TemporaryChannelCannotBeLinked(linked_id));
        }
    }
    Ok(())
}

fn apply_link_topology_effect(
    link_topologies: &ParkingRwLock<HashMap<String, LinkTopology>>,
    server_id: &str,
    channels: &mut HashMap<u32, Channel>,
    effect: LinkTopologyEffect,
) {
    match effect {
        LinkTopologyEffect::Unchanged => {}
        LinkTopologyEffect::DeletedChannels(deleted_ids) => {
            let mut link_topologies = link_topologies.write();
            if let Some(topology) = link_topologies.get_mut(server_id) {
                topology.remove_deleted_channels(channels, &deleted_ids);
            } else {
                sync_link_topology_for_server(&mut link_topologies, server_id, channels);
            }
        }
        LinkTopologyEffect::Rebuild => {
            let mut link_topologies = link_topologies.write();
            sync_link_topology_for_server(&mut link_topologies, server_id, channels);
        }
    }
}

/// Apply a `ChannelOp` to the in-memory channel map.
fn apply_op_to_map(
    channels: &mut HashMap<u32, Channel>,
    op: &ChannelOp,
    origin_node: u16,
    root_config: &ChannelRootConfig,
) {
    let op = normalize_op_for_root(op, root_config);
    match &op {
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
        ChannelOp::MarkPendingDelete { id, nonce, .. } => {
            let started_at_ms = chrono::Utc::now().timestamp_millis();
            let to_mark = collect_subtree(channels, *id);
            for mark_id in to_mark {
                if let Some(ch) = channels.get_mut(&mark_id) {
                    ch.pending_delete = Some(PendingDeleteState {
                        nonce: *nonce,
                        started_at_ms,
                        origin_node,
                    });
                }
            }
        }
        ChannelOp::DeleteChannel { id, nonce } => {
            let _ = apply_delete_channel_to_map(channels, *id, *nonce);
        }
        ChannelOp::CancelPendingDelete { id, nonce } => {
            let to_cancel = collect_subtree(channels, *id);
            for cancel_id in to_cancel {
                if let Some(ch) = channels.get_mut(&cancel_id) {
                    if ch
                        .pending_delete
                        .as_ref()
                        .is_some_and(|pending| pending.nonce == *nonce)
                    {
                        ch.pending_delete = None;
                    }
                }
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
        ChannelOp::InstallSnapshot {
            channels: snapshot, ..
        } => {
            channels.clear();
            for channel in snapshot {
                let mut channel = channel.clone();
                if channel.id == 0 {
                    channel.name = root_config.name().to_owned();
                }
                channels.insert(channel.id, channel);
            }
            ensure_root_channel(channels, root_config);
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

fn apply_delete_channel_to_map(
    channels: &mut HashMap<u32, Channel>,
    id: u32,
    nonce: u64,
) -> Option<DeleteChannelApplied> {
    let channel = channels.get(&id)?;
    if !channel
        .pending_delete
        .as_ref()
        .is_some_and(|pending| pending.nonce == nonce)
    {
        return None;
    }

    let to_delete = collect_subtree(channels, id);
    let link_topology_effect = if deleted_channels_have_links(channels, &to_delete) {
        LinkTopologyEffect::DeletedChannels(to_delete.clone())
    } else {
        LinkTopologyEffect::Unchanged
    };
    let external_link_neighbors = linked_neighbors_outside_deleted_subtree(channels, &to_delete);

    for del_id in &to_delete {
        channels.remove(del_id);
    }
    remove_links_from_deleted_channel_neighbors(channels, &external_link_neighbors, &to_delete);

    Some(DeleteChannelApplied {
        deleted_ids: to_delete,
        link_topology_effect,
    })
}

fn rebuild_all_link_topologies(
    channels_by_server: &mut HashMap<String, HashMap<u32, Channel>>,
) -> HashMap<String, LinkTopology> {
    let mut topologies = HashMap::new();
    for (server_id, channels) in channels_by_server {
        normalize_channel_links(channels);
        topologies.insert(server_id.clone(), LinkTopology::from_channels(channels));
    }
    topologies
}

fn sync_link_topology_for_server(
    link_topologies: &mut HashMap<String, LinkTopology>,
    server_id: &str,
    channels: &mut HashMap<u32, Channel>,
) {
    normalize_channel_links(channels);
    link_topologies.insert(server_id.to_owned(), LinkTopology::from_channels(channels));
}

fn normalize_channel_links(channels: &mut HashMap<u32, Channel>) {
    let channel_ids: HashSet<u32> = channels.keys().copied().collect();
    let mut edges = HashSet::new();

    for (&id, channel) in channels.iter() {
        for &linked_id in &channel.links {
            if linked_id == id || !channel_ids.contains(&linked_id) {
                continue;
            }
            edges.insert(ordered_link_edge(id, linked_id));
        }
    }

    for channel in channels.values_mut() {
        channel.links.clear();
    }

    for (a, b) in edges {
        if let Some(channel) = channels.get_mut(&a) {
            channel.links.insert(b);
        }
        if let Some(channel) = channels.get_mut(&b) {
            channel.links.insert(a);
        }
    }
}

fn deleted_channels_have_links(channels: &HashMap<u32, Channel>, deleted_ids: &[u32]) -> bool {
    deleted_ids.iter().any(|id| {
        channels
            .get(id)
            .is_some_and(|channel| !channel.links.is_empty())
    })
}

fn linked_neighbors_outside_deleted_subtree(
    channels: &HashMap<u32, Channel>,
    deleted_ids: &[u32],
) -> Vec<u32> {
    let deleted_ids: HashSet<u32> = deleted_ids.iter().copied().collect();
    let mut neighbors = HashSet::new();
    for deleted_id in &deleted_ids {
        if let Some(channel) = channels.get(deleted_id) {
            for &linked_id in &channel.links {
                if !deleted_ids.contains(&linked_id) {
                    neighbors.insert(linked_id);
                }
            }
        }
    }
    neighbors.into_iter().collect()
}

fn remove_links_from_deleted_channel_neighbors(
    channels: &mut HashMap<u32, Channel>,
    neighbor_ids: &[u32],
    removed_ids: &[u32],
) {
    if neighbor_ids.is_empty() || removed_ids.is_empty() {
        return;
    }
    let removed_ids: HashSet<u32> = removed_ids.iter().copied().collect();
    for neighbor_id in neighbor_ids {
        if let Some(channel) = channels.get_mut(neighbor_id) {
            channel
                .links
                .retain(|linked_id| !removed_ids.contains(linked_id));
        }
    }
}

fn ordered_link_edge(a: u32, b: u32) -> (u32, u32) {
    if a < b { (a, b) } else { (b, a) }
}

fn ensure_root_channel(channels: &mut HashMap<u32, Channel>, root_config: &ChannelRootConfig) {
    channels
        .entry(0)
        .or_insert_with(|| root_channel(root_config));
    if let Some(root) = channels.get_mut(&0) {
        root.name = root_config.name().to_owned();
        root.parent_id = None;
    }
}

fn root_channel(root_config: &ChannelRootConfig) -> Channel {
    Channel::new(0, root_config.name().to_owned(), 0, 0, None)
}

fn normalize_root_patch(mut patch: ChannelPatch) -> ChannelPatch {
    if patch.name.is_some() {
        patch.name = None;
    }
    patch.parent_id = None;
    patch
}

fn normalize_op_for_root(op: &ChannelOp, root_config: &ChannelRootConfig) -> ChannelOp {
    match op {
        ChannelOp::CreateChannel { channel } if channel.id == 0 => {
            let mut channel = channel.clone();
            channel.name = root_config.name().to_owned();
            channel.parent_id = None;
            ChannelOp::CreateChannel { channel }
        }
        ChannelOp::EditChannel {
            id,
            patch,
            links_add,
            links_remove,
        } if *id == 0 => ChannelOp::EditChannel {
            id: *id,
            patch: normalize_root_patch(patch.clone()),
            links_add: links_add.clone(),
            links_remove: links_remove.clone(),
        },
        ChannelOp::UpdateChannel { id, patch } if *id == 0 => ChannelOp::UpdateChannel {
            id: *id,
            patch: normalize_root_patch(patch.clone()),
        },
        ChannelOp::InstallSnapshot { channels, removed } => ChannelOp::InstallSnapshot {
            channels: channels
                .iter()
                .cloned()
                .map(|mut channel| {
                    if channel.id == 0 {
                        channel.name = root_config.name().to_owned();
                        channel.parent_id = None;
                    }
                    channel
                })
                .collect(),
            removed: removed.clone(),
        },
        _ => op.clone(),
    }
}

impl ChannelSnapshotState {
    fn from_channel(channel: &Channel) -> Self {
        Self {
            id: channel.id,
            name: (channel.id != 0).then(|| channel.name.clone()),
            position: channel.position,
            max_users: channel.max_users,
            parent_id: channel.parent_id,
            inherit_acl: channel.inherit_acl,
            links: channel.links.clone(),
            description_hash: channel.description_hash.clone(),
            acls: channel.acls.clone(),
            pending_delete: channel.pending_delete.clone(),
        }
    }

    fn into_channel(self, root_config: &ChannelRootConfig) -> Channel {
        Channel {
            id: self.id,
            name: if self.id == 0 {
                root_config.name().to_owned()
            } else {
                self.name.unwrap_or_else(|| "Unnamed".to_owned())
            },
            position: self.position,
            max_users: self.max_users,
            parent_id: if self.id == 0 { None } else { self.parent_id },
            inherit_acl: self.inherit_acl,
            links: self.links,
            description_hash: self.description_hash,
            acls: self.acls,
            pending_delete: self.pending_delete,
        }
    }
}

pub fn channel_op_affects_acl_generation(op: &ChannelOp) -> bool {
    match op {
        ChannelOp::CreateChannel { .. }
        | ChannelOp::DeleteChannel { .. }
        | ChannelOp::SetAcls { .. }
        | ChannelOp::InstallSnapshot { .. } => true,
        ChannelOp::UpdateChannel { patch, .. } | ChannelOp::EditChannel { patch, .. } => {
            patch.parent_id.is_some()
        }
        ChannelOp::AddLink { .. }
        | ChannelOp::RemoveLink { .. }
        | ChannelOp::MarkPendingDelete { .. }
        | ChannelOp::CancelPendingDelete { .. } => false,
    }
}

pub fn channel_op_invalidates_acl_cache(op: &ChannelOp) -> bool {
    channel_op_affects_acl_generation(op) && !matches!(op, ChannelOp::CreateChannel { .. })
}

fn acl_affected_channel_ids_for_op_in_map(
    channels: &HashMap<u32, Channel>,
    op: &ChannelOp,
) -> Option<HashSet<u32>> {
    match op {
        ChannelOp::CreateChannel { .. } => Some(HashSet::new()),
        ChannelOp::SetAcls { channel_id, .. } => {
            Some(collect_subtree(channels, *channel_id).into_iter().collect())
        }
        ChannelOp::UpdateChannel { id, patch } | ChannelOp::EditChannel { id, patch, .. }
            if patch.parent_id.is_some() =>
        {
            let mut affected: HashSet<u32> = collect_subtree(channels, *id).into_iter().collect();
            affected.extend(channels_with_home_channel_dependent_acls_in_map(channels));
            Some(affected)
        }
        ChannelOp::DeleteChannel { .. } => Some(HashSet::new()),
        ChannelOp::InstallSnapshot { channels, .. } => {
            Some(channels.iter().map(|channel| channel.id).collect())
        }
        ChannelOp::UpdateChannel { .. }
        | ChannelOp::EditChannel { .. }
        | ChannelOp::MarkPendingDelete { .. }
        | ChannelOp::CancelPendingDelete { .. }
        | ChannelOp::AddLink { .. }
        | ChannelOp::RemoveLink { .. } => Some(HashSet::new()),
    }
}

fn channels_with_home_channel_dependent_acls_in_map(
    channels: &HashMap<u32, Channel>,
) -> HashSet<u32> {
    let mut children_by_parent: HashMap<Option<u32>, Vec<u32>> = HashMap::new();
    for channel in channels.values() {
        children_by_parent
            .entry(channel.parent_id)
            .or_default()
            .push(channel.id);
    }

    let mut roots: Vec<u32> = channels
        .values()
        .filter(|channel| {
            channel
                .parent_id
                .is_none_or(|parent_id| !channels.contains_key(&parent_id))
        })
        .map(|channel| channel.id)
        .collect();
    roots.sort_unstable();

    let mut affected = HashSet::new();
    for root_id in roots {
        collect_home_channel_dependent_acl_channel_ids(
            channels,
            &children_by_parent,
            root_id,
            false,
            &mut affected,
        );
    }
    affected
}

fn collect_home_channel_dependent_acl_channel_ids(
    channels: &HashMap<u32, Channel>,
    children_by_parent: &HashMap<Option<u32>, Vec<u32>>,
    channel_id: u32,
    inherited_home_channel_dependent_acl: bool,
    affected: &mut HashSet<u32>,
) {
    let Some(channel) = channels.get(&channel_id) else {
        return;
    };
    let inherited_home_channel_dependent_acl =
        channel.inherit_acl && inherited_home_channel_dependent_acl;
    let applies_here = inherited_home_channel_dependent_acl
        || channel.acls.iter().any(|acl| {
            acl.apply_here
                && acl
                    .group
                    .as_deref()
                    .is_some_and(group_depends_on_home_channel_for_cache_scope)
        });
    let applies_to_subs = channel.acls.iter().any(|acl| {
        acl.apply_subs
            && acl
                .group
                .as_deref()
                .is_some_and(group_depends_on_home_channel_for_cache_scope)
    });

    if applies_here {
        affected.insert(channel_id);
    }

    let descendant_inherited = inherited_home_channel_dependent_acl || applies_to_subs;
    if let Some(children) = children_by_parent.get(&Some(channel_id)) {
        for child_id in children {
            collect_home_channel_dependent_acl_channel_ids(
                channels,
                children_by_parent,
                *child_id,
                descendant_inherited,
                affected,
            );
        }
    }
}

fn group_depends_on_home_channel_for_cache_scope(group: &str) -> bool {
    let mut group = group;
    while let Some(stripped) = group.strip_prefix('!') {
        group = stripped;
    }
    if let Some(stripped) = group.strip_prefix('~') {
        group = stripped;
    }
    matches!(group, "in" | "out") || group.starts_with("sub")
}

/// Collect `root_id` and all of its descendants (BFS), returning their IDs.
fn collect_subtree(channels: &HashMap<u32, Channel>, root_id: u32) -> Vec<u32> {
    if channels
        .get(&root_id)
        .is_some_and(|channel| channel.is_temporary())
    {
        return vec![root_id];
    }

    let mut children_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
    for channel in channels.values() {
        if let Some(parent_id) = channel.parent_id {
            children_by_parent
                .entry(parent_id)
                .or_default()
                .push(channel.id);
        }
    }

    let mut result = vec![root_id];
    let mut queue = VecDeque::new();
    queue.push_back(root_id);
    while let Some(id) = queue.pop_front() {
        if let Some(children) = children_by_parent.get(&id) {
            for &child_id in children {
                result.push(child_id);
                queue.push_back(child_id);
            }
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingObserver {
        versions: Mutex<Vec<(String, u64)>>,
        repairs: Mutex<Vec<(String, HashSet<u32>, u64)>>,
    }

    #[async_trait]
    impl ChannelRepositoryObserver for RecordingObserver {
        async fn channel_version_advanced(&self, server_id: &str, channel_version: u64) {
            self.versions
                .lock()
                .expect("recording observer mutex poisoned")
                .push((server_id.to_owned(), channel_version));
        }

        async fn repair_missing_channels(
            &self,
            server_id: &str,
            valid_channel_ids: &HashSet<u32>,
            channel_version: u64,
        ) -> usize {
            self.repairs
                .lock()
                .expect("recording observer mutex poisoned")
                .push((
                    server_id.to_owned(),
                    valid_channel_ids.clone(),
                    channel_version,
                ));
            0
        }
    }

    fn tuning() -> ChannelRepoTuning {
        ChannelRepoTuning {
            log_max_entries: 100,
            snapshot_every_ops: 100,
            snapshot_every_secs: 60,
            wal_compaction_expire_count: 100,
        }
    }

    fn root_config() -> ChannelRootConfig {
        ChannelRootConfig::new("Root")
    }

    fn repo() -> Arc<ChannelRepository> {
        ChannelRepository::new_in_memory(1, root_config(), tuning())
    }

    fn repo_with_log_max_entries(log_max_entries: usize) -> Arc<ChannelRepository> {
        ChannelRepository::new_in_memory(
            1,
            root_config(),
            ChannelRepoTuning {
                log_max_entries,
                ..tuning()
            },
        )
    }

    fn effective_group(repo: &ChannelRepository, channel_id: u32) -> Vec<u32> {
        repo.effective_link_group_in_server(DEFAULT_SERVER_ID, channel_id)
            .map(|group| group.as_ref().to_vec())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn linked_channels_form_effective_transitive_groups() {
        let repo = repo();
        for id in 1..=3 {
            repo.create_channel(Channel::new(id, format!("ch{id}"), 0, 0, Some(0)))
                .await
                .unwrap();
        }

        repo.add_link(1, 2).await.unwrap();
        repo.add_link(2, 3).await.unwrap();

        assert_eq!(effective_group(&repo, 1), vec![1, 2, 3]);
        assert_eq!(effective_group(&repo, 2), vec![1, 2, 3]);
        assert_eq!(effective_group(&repo, 3), vec![1, 2, 3]);

        let ch1 = repo.get_channel(1).await.unwrap();
        assert_eq!(ch1.links, HashSet::from([2]));
    }

    #[tokio::test]
    async fn temporary_channels_cannot_have_children_or_links() {
        let repo = repo();
        let temp_id = TEMPORARY_CHANNEL_ID_BIT | 1;
        repo.create_channel(Channel::new(temp_id, "temp", 0, 0, Some(0)))
            .await
            .unwrap();

        let child = repo
            .create_channel(Channel::new(10, "child", 0, 0, Some(temp_id)))
            .await;
        assert!(matches!(
            child,
            Err(ChannelRepoError::TemporaryChannelCannotHaveChildren(id)) if id == temp_id
        ));

        repo.create_channel(Channel::new(10, "ordinary", 0, 0, Some(0)))
            .await
            .unwrap();

        let moved_child = repo
            .update_channel(
                10,
                ChannelPatch {
                    name: None,
                    position: None,
                    max_users: None,
                    description_hash: None,
                    parent_id: Some(Some(temp_id)),
                },
            )
            .await;
        assert!(matches!(
            moved_child,
            Err(ChannelRepoError::TemporaryChannelCannotHaveChildren(id)) if id == temp_id
        ));

        let linked = repo.add_link(temp_id, 10).await;
        assert!(matches!(
            linked,
            Err(ChannelRepoError::TemporaryChannelCannotBeLinked(id)) if id == temp_id
        ));

        let edit_link = repo
            .edit_channel(
                10,
                ChannelPatch {
                    name: None,
                    position: None,
                    max_users: None,
                    description_hash: None,
                    parent_id: None,
                },
                vec![temp_id],
                Vec::new(),
            )
            .await;
        assert!(matches!(
            edit_link,
            Err(ChannelRepoError::TemporaryChannelCannotBeLinked(id)) if id == temp_id
        ));
    }

    #[test]
    fn temporary_subtree_collection_is_leaf_only() {
        let temp_id = TEMPORARY_CHANNEL_ID_BIT | 1;
        let mut channels = HashMap::new();
        channels.insert(temp_id, Channel::new(temp_id, "temp", 0, 0, Some(0)));
        channels.insert(10, Channel::new(10, "legacy-child", 0, 0, Some(temp_id)));

        assert_eq!(collect_subtree(&channels, temp_id), vec![temp_id]);
    }

    #[tokio::test]
    async fn removing_link_splits_effective_group_only_when_connectivity_breaks() {
        let repo = repo();
        for id in 1..=3 {
            repo.create_channel(Channel::new(id, format!("ch{id}"), 0, 0, Some(0)))
                .await
                .unwrap();
        }

        repo.add_link(1, 2).await.unwrap();
        repo.add_link(2, 3).await.unwrap();
        repo.add_link(1, 3).await.unwrap();
        repo.remove_link(2, 3).await.unwrap();

        assert_eq!(effective_group(&repo, 1), vec![1, 2, 3]);
        assert_eq!(effective_group(&repo, 3), vec![1, 2, 3]);

        repo.remove_link(1, 3).await.unwrap();

        assert_eq!(effective_group(&repo, 1), vec![1, 2]);
        assert_eq!(effective_group(&repo, 2), vec![1, 2]);
        assert!(effective_group(&repo, 3).is_empty());
    }

    #[tokio::test]
    async fn deleting_channel_removes_it_from_link_topology() {
        let repo = repo();
        for id in 1..=3 {
            repo.create_channel(Channel::new(id, format!("ch{id}"), 0, 0, Some(0)))
                .await
                .unwrap();
        }

        repo.add_link(1, 2).await.unwrap();
        repo.add_link(2, 3).await.unwrap();
        repo.mark_pending_delete(2, 99).await.unwrap();
        repo.apply_delete_channel(2, 99).await.unwrap();

        assert!(effective_group(&repo, 1).is_empty());
        assert!(effective_group(&repo, 3).is_empty());
        assert!(repo.get_channel(1).await.unwrap().links.is_empty());
        assert!(repo.get_channel(3).await.unwrap().links.is_empty());
    }

    #[tokio::test]
    async fn deleting_linked_channel_updates_only_affected_link_component() {
        let repo = repo();
        for id in 1..=6 {
            repo.create_channel(Channel::new(id, format!("ch{id}"), 0, 0, Some(0)))
                .await
                .unwrap();
        }

        repo.add_link(1, 2).await.unwrap();
        repo.add_link(2, 3).await.unwrap();
        repo.add_link(4, 5).await.unwrap();
        repo.mark_pending_delete(2, 99).await.unwrap();
        repo.apply_delete_channel(2, 99).await.unwrap();

        assert!(effective_group(&repo, 1).is_empty());
        assert!(effective_group(&repo, 3).is_empty());
        assert_eq!(effective_group(&repo, 4), vec![4, 5]);
        assert_eq!(effective_group(&repo, 5), vec![4, 5]);
        assert!(effective_group(&repo, 6).is_empty());
        assert!(repo.get_channel(1).await.unwrap().links.is_empty());
        assert!(repo.get_channel(3).await.unwrap().links.is_empty());
    }

    #[tokio::test]
    async fn delete_visibility_hint_is_stored_for_successful_delete() {
        let repo = repo();
        repo.create_channel(Channel::new(2, "parent", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(3, "child", 0, 0, Some(2)))
            .await
            .unwrap();
        repo.mark_pending_delete(2, 99).await.unwrap();
        repo.apply_delete_channel(2, 99).await.unwrap();

        let op = repo
            .get_log_since(0)
            .await
            .into_iter()
            .find(|op| matches!(op.op, ChannelOp::DeleteChannel { id: 2, .. }))
            .expect("delete op");
        let hint = repo
            .delete_visibility_hint_for_operation(&op)
            .expect("successful delete stores hint");

        assert_eq!(hint.as_ref(), &[2, 3]);
    }

    #[tokio::test]
    async fn delete_visibility_hint_is_absent_for_stale_no_op_delete() {
        let repo = repo();
        repo.create_channel(Channel::new(2, "parent", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.mark_pending_delete(2, 99).await.unwrap();
        repo.apply_delete_channel(2, 100).await.unwrap();

        let op = repo
            .get_log_since(0)
            .await
            .into_iter()
            .find(|op| matches!(op.op, ChannelOp::DeleteChannel { id: 2, .. }))
            .expect("delete op");

        assert!(repo.delete_visibility_hint_for_operation(&op).is_none());
    }

    #[tokio::test]
    async fn delete_visibility_hint_is_pruned_with_channel_log() {
        let repo = repo_with_log_max_entries(1);
        repo.create_channel(Channel::new(2, "doomed", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.mark_pending_delete(2, 99).await.unwrap();
        repo.apply_delete_channel(2, 99).await.unwrap();
        let delete_op = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: repo.current_version(),
            node_id: 1,
            timestamp: 0,
            emits_client_message: true,
            op: ChannelOp::DeleteChannel { id: 2, nonce: 99 },
        };

        assert!(
            repo.delete_visibility_hint_for_operation(&delete_op)
                .is_some()
        );

        repo.create_channel(Channel::new(3, "after", 0, 0, Some(0)))
            .await
            .unwrap();

        assert!(
            repo.delete_visibility_hint_for_operation(&delete_op)
                .is_none()
        );
    }

    #[tokio::test]
    async fn persisted_repository_rebuilds_effective_link_groups() {
        let temp = tempfile::tempdir().unwrap();

        {
            let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
                .await
                .unwrap();
            for id in 1..=3 {
                repo.create_channel(Channel::new(id, format!("ch{id}"), 0, 0, Some(0)))
                    .await
                    .unwrap();
            }
            repo.add_link(1, 2).await.unwrap();
            repo.add_link(2, 3).await.unwrap();
            repo.save_snapshot().await.unwrap();
        }

        let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
            .await
            .unwrap();

        assert_eq!(effective_group(&repo, 1), vec![1, 2, 3]);
        assert_eq!(effective_group(&repo, 3), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn root_channel_name_is_loaded_from_config_not_snapshot() {
        let temp = tempfile::tempdir().unwrap();

        {
            let repo = ChannelRepository::open(
                1,
                temp.path(),
                ChannelRootConfig::new("Configured Root"),
                tuning(),
            )
            .await
            .unwrap();
            repo.set_acls(0, false, Vec::new()).await.unwrap();
            repo.save_snapshot().await.unwrap();

            let raw = std::fs::read_to_string(temp.path().join("channels.snapshot.json")).unwrap();
            let snapshot: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let root = snapshot["channels"]
                .as_array()
                .unwrap()
                .iter()
                .find(|channel| channel["id"] == 0)
                .expect("root channel is snapshotted");
            assert!(
                root.get("name").is_none(),
                "root channel name must not be serialized into the channel snapshot"
            );
        }

        let repo = ChannelRepository::open(
            1,
            temp.path(),
            ChannelRootConfig::new("Renamed By Config"),
            tuning(),
        )
        .await
        .unwrap();
        let root = repo.get_channel(0).await.unwrap();
        assert_eq!(root.name, "Renamed By Config");
        assert!(
            !root.inherit_acl,
            "non-name root channel state should still be loaded from the snapshot/WAL"
        );
    }

    #[tokio::test]
    async fn root_channel_name_patches_are_normalized_to_config() {
        let repo = ChannelRepository::new_in_memory(
            1,
            ChannelRootConfig::new("Configured Root"),
            tuning(),
        );

        let updated = repo
            .update_channel(
                0,
                ChannelPatch {
                    name: Some("Ignored Patch".to_owned()),
                    position: Some(7),
                    max_users: None,
                    description_hash: None,
                    parent_id: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(updated.name, "Configured Root");
        assert_eq!(updated.position, 7);
        assert_eq!(repo.get_channel(0).await.unwrap().name, "Configured Root");
    }

    #[tokio::test]
    async fn update_channel_does_not_hold_channels_lock_while_committing() {
        let temp = tempfile::tempdir().unwrap();
        let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
            .await
            .unwrap();
        repo.create_channel(Channel::new(7, "old", 0, 0, Some(0)))
            .await
            .unwrap();

        let wal_guard = repo
            .wal_file
            .as_ref()
            .expect("persisted repository has a WAL")
            .lock()
            .await;
        let mut update = tokio::spawn({
            let repo = Arc::clone(&repo);
            async move {
                repo.update_channel(
                    7,
                    ChannelPatch {
                        name: Some("new".to_owned()),
                        position: None,
                        max_users: None,
                        description_hash: None,
                        parent_id: None,
                    },
                )
                .await
            }
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut update)
                .await
                .is_err(),
            "precondition: channel update should be waiting for the WAL commit"
        );

        let channel =
            tokio::time::timeout(std::time::Duration::from_millis(50), repo.get_channel(7))
                .await
                .expect("channel reads should not wait behind a blocked commit")
                .expect("channel exists");
        assert_eq!(channel.name, "new");

        drop(wal_guard);
        update.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stale_nonce_delete_is_semantic_no_op() {
        let repo = repo();
        repo.create_channel(Channel::new(7, "doomed", 0, 0, Some(0)))
            .await
            .unwrap();

        repo.mark_pending_delete(7, 10).await.unwrap();
        repo.cancel_pending_delete(7, 10).await.unwrap();
        let deleted = repo.apply_delete_channel(7, 10).await.unwrap();

        assert!(!deleted);
        assert!(repo.get_channel(7).await.is_some());
        let last = repo.get_log_since(0).await.pop().unwrap();
        assert!(last.to_message().is_none());
    }

    #[tokio::test]
    async fn matching_nonce_delete_removes_subtree_and_emits_remove() {
        let repo = repo();
        repo.create_channel(Channel::new(7, "parent", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(8, "child", 0, 0, Some(7)))
            .await
            .unwrap();

        let marked = repo.mark_pending_delete(7, 99).await.unwrap();
        assert_eq!(marked.len(), 2);
        let deleted = repo.apply_delete_channel(7, 99).await.unwrap();

        assert!(deleted);
        assert!(repo.get_channel(7).await.is_none());
        assert!(repo.get_channel(8).await.is_none());
        let last = repo.get_log_since(0).await.pop().unwrap();
        assert!(matches!(
            last.to_message(),
            Some(shitspeak_messages::messages::Message::ChannelRemove(_))
        ));
    }

    #[tokio::test]
    async fn duplicate_channel_ids_are_isolated_by_server_id() {
        let repo = repo();

        repo.create_channel_in_server("alpha", Channel::new(7, "alpha", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.create_channel_in_server("beta", Channel::new(7, "beta", 0, 0, Some(0)))
            .await
            .unwrap();

        assert_eq!(
            repo.get_channel_in_server("alpha", 7).await.unwrap().name,
            "alpha"
        );
        assert_eq!(
            repo.get_channel_in_server("beta", 7).await.unwrap().name,
            "beta"
        );
        assert_eq!(repo.len_in_server("alpha").await, 2);
        assert_eq!(repo.len_in_server("beta").await, 2);
    }

    #[tokio::test]
    async fn stale_allocated_channel_id_does_not_overwrite_existing_channel() {
        let repo = repo();
        let stale_id = repo.next_channel_id(true).await;

        repo.create_channel(Channel::new(stale_id, "first", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(stale_id, "second", 0, 0, Some(0)))
            .await
            .unwrap();

        let first = repo
            .get_channel(stale_id)
            .await
            .expect("first channel should still exist at its original id");
        assert_eq!(first.name, "first");
        assert!(
            repo.get_all()
                .await
                .into_iter()
                .any(|channel| channel.id != stale_id && channel.name == "second"),
            "second channel should be assigned a fresh id instead of replacing the first"
        );
    }

    #[tokio::test]
    async fn subscribed_snapshot_receives_followup_channel_operations() {
        let repo = repo();
        let (channels, version, mut rx) =
            repo.snapshot_with_version_and_subscription_in_server("alpha");

        assert_eq!(version, 0);
        assert!(channels.iter().any(|channel| channel.id == 0));

        repo.create_channel_in_server("alpha", Channel::new(7, "alpha", 0, 0, Some(0)))
            .await
            .unwrap();

        let op = rx
            .try_recv()
            .expect("snapshot subscription receives channel operation");
        assert_eq!(op.server_id, "alpha");
        assert_eq!(op.version, 1);
    }

    #[tokio::test]
    async fn s2s_snapshot_install_notifies_the_state_observer() {
        let repo = repo();
        let observer = Arc::new(RecordingObserver::default());
        repo.set_observer(observer.clone());

        repo.create_channel(Channel::new(7, "kept", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(8, "removed", 0, 0, Some(0)))
            .await
            .unwrap();

        repo.install_s2s_snapshot(3, vec![Channel::new(7, "kept", 0, 0, Some(0))])
            .await
            .unwrap();

        assert!(repo.get_channel(8).await.is_none());
        assert_eq!(
            observer
                .versions
                .lock()
                .expect("recording observer mutex poisoned")
                .last(),
            Some(&(DEFAULT_SERVER_ID.to_owned(), 3))
        );
        let repairs = observer
            .repairs
            .lock()
            .expect("recording observer mutex poisoned");
        let (_, valid_channel_ids, version) = repairs.last().expect("repair callback was invoked");
        assert_eq!(*version, 3);
        assert!(valid_channel_ids.contains(&0));
        assert!(valid_channel_ids.contains(&7));
        assert!(!valid_channel_ids.contains(&8));
    }

    #[tokio::test]
    async fn committed_channel_operation_preserves_strict_metadata_in_replay_log() {
        let repo = repo();
        let metadata = StrictReplicationMetadata::new(11, 22, 33);
        let op = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 123,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "strict", 0, 0, Some(0)),
            },
        };

        repo.apply_committed_operation_with_metadata(op, Some(metadata))
            .await
            .unwrap();

        let entries = repo
            .get_log_entries_since_in_server(DEFAULT_SERVER_ID, 0)
            .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op().version, 1);
        assert_eq!(entries[0].strict_metadata(), Some(metadata));
    }

    #[tokio::test]
    async fn persisted_channel_wal_preserves_strict_metadata_in_replay_log() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = StrictReplicationMetadata::new(u64::MAX - 2, u64::MAX - 1, u64::MAX);

        {
            let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
                .await
                .unwrap();
            let op = ChannelOperation {
                server_id: DEFAULT_SERVER_ID.to_owned(),
                version: 1,
                node_id: 1,
                timestamp: 123,
                emits_client_message: true,
                op: ChannelOp::CreateChannel {
                    channel: Channel::new(9, "strict", 0, 0, Some(0)),
                },
            };
            repo.apply_committed_operation_with_metadata(op, Some(metadata))
                .await
                .unwrap();
        }

        let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
            .await
            .unwrap();
        let entries = repo
            .get_log_entries_since_in_server(DEFAULT_SERVER_ID, 0)
            .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].op().version, 1);
        assert_eq!(entries[0].strict_metadata(), Some(metadata));
    }
}
