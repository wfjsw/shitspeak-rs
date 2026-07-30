//! `ChannelRepository` — versioned, WAL-persisted, snapshotted channel store.
//!
//! # Persistence
//!
//! When a `storage_dir` is configured:
//!
//! * `<dir>/channels.snapshot.json` — full snapshot of the channel map.
//! * `<dir>/channels.wal.jsonl`     — append-only newline-delimited JSON log.
//! * `<dir>/channels.effective-acl-cache.json` — disposable, version-locked
//!   checkpoint of the derived per-channel ACL programs.
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
//! Each channel owns a derived, compiled effective ACL program that is rebuilt
//! after load and whenever its tree path can change. Per-client permission
//! results are also cached after first computation and generation-invalidated
//! when ACL or client membership state changes. The evaluator lives in
//! `acl.rs`; the repository maintains both cache lifecycles.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
use enumflags2::BitFlags;
use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use rustc_hash::FxHasher;
use scc::HashCache;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Mutex as AsyncMutex, broadcast};

use crate::{
    ACL, ACLPermissions, AclChangeImpact, Channel, ChannelPatch, ChannelRepoError,
    PendingDeleteState, classify_acl_change, group_depends_on_home_channel,
};
use shitspeak_core::{DEFAULT_SERVER_ID, StrictReplicationMetadata, default_server_id};
use shitspeak_messages::messages::{Message, encoder};

const TEMPORARY_CHANNEL_ID_BIT: u32 = 0x8000_0000;
const EFFECTIVE_ACL_CACHE_FORMAT_VERSION: u32 = 3;

type ChannelMap = HashMap<u32, Arc<Channel>>;
type ChannelsByServer = HashMap<String, ChannelMap>;
pub type OrderedChannelSnapshot = Arc<[Arc<Channel>]>;

#[cfg(windows)]
const REPLACEFILE_WRITE_THROUGH: u32 = 0x0000_0001;
#[cfg(windows)]
const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
#[cfg(windows)]
const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

#[cfg(windows)]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn ReplaceFileW(
        replaced_file_name: *const u16,
        replacement_file_name: *const u16,
        backup_file_name: *const u16,
        replace_flags: u32,
        exclude: *mut std::ffi::c_void,
        reserved: *mut std::ffi::c_void,
    ) -> i32;
    fn MoveFileExW(
        existing_file_name: *const u16,
        new_file_name: *const u16,
        move_flags: u32,
    ) -> i32;
}

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

/// Result of applying a strict-replication operation through the durable
/// idempotency boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictOperationApplyOutcome {
    /// This operation id was not previously recorded and the operation was applied.
    Applied,
    /// This operation id was already committed, so no state was changed.
    AlreadyApplied,
    /// The operation id is unknown, but its version is already covered by
    /// different committed state. The caller must recover rather than treating
    /// this as a successful duplicate.
    VersionConflict,
}

impl StrictOperationApplyOutcome {
    pub fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// Stable identifier for a strict operation. `ts_final` deliberately is not
/// part of the id: a retried operation is identified solely by its op id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StrictOperationId {
    op_id_hi: u64,
    op_id_lo: u64,
}

impl StrictOperationId {
    pub fn new(op_id_hi: u64, op_id_lo: u64) -> Self {
        Self { op_id_hi, op_id_lo }
    }

    pub fn op_id_hi(&self) -> u64 {
        self.op_id_hi
    }

    pub fn op_id_lo(&self) -> u64 {
        self.op_id_lo
    }

    fn from_metadata(metadata: StrictReplicationMetadata) -> Self {
        Self::new(metadata.op_id_hi(), metadata.op_id_lo())
    }
}

/// A single, internally consistent channel replication snapshot.
///
/// The fields remain private so callers cannot construct a bundle whose
/// channel state, version, and idempotency ledger describe different points in
/// time. Use [`Self::into_parts`] when serializing it for replication.
#[derive(Debug, Clone)]
pub struct ChannelStrictSnapshot {
    version: u64,
    channels: Vec<Channel>,
    freshness: i64,
    operation_ids: Vec<StrictOperationId>,
}

impl ChannelStrictSnapshot {
    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn channels(&self) -> &[Channel] {
        &self.channels
    }

    pub fn freshness(&self) -> i64 {
        self.freshness
    }

    pub fn operation_ids(&self) -> &[StrictOperationId] {
        &self.operation_ids
    }

    pub fn into_parts(self) -> (u64, Vec<Channel>, i64, Vec<StrictOperationId>) {
        (
            self.version,
            self.channels,
            self.freshness,
            self.operation_ids,
        )
    }
}

/// Channel strict topics independently allocate operation ids, so the durable
/// channel ledger also retains the server scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct StrictOperationKey {
    server_id: String,
    operation_id: StrictOperationId,
}

impl StrictOperationKey {
    fn new(server_id: impl Into<String>, metadata: StrictReplicationMetadata) -> Self {
        Self {
            server_id: server_id.into(),
            operation_id: StrictOperationId::from_metadata(metadata),
        }
    }

    fn with_operation_id(server_id: impl Into<String>, operation_id: StrictOperationId) -> Self {
        Self {
            server_id: server_id.into(),
            operation_id,
        }
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
    /// New strict replication owns delivery deduplication in its terminal
    /// journal. Keep the metadata for catchup, but do not rebuild the legacy
    /// repository op-id ledger from these records during startup.
    #[serde(default, skip_serializing_if = "is_false")]
    strict_id_owned_by_s2s: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl ChannelWalRecord {
    fn new(
        op: &ChannelOperation,
        strict_metadata: Option<StrictReplicationMetadata>,
        strict_id_owned_by_s2s: bool,
    ) -> Self {
        Self {
            op: op.clone(),
            strict_metadata,
            strict_id_owned_by_s2s,
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
    /// Strict operation ids reflected in this snapshot. WAL compaction may
    /// remove the associated records, so this ledger is part of durable state.
    #[serde(default)]
    strict_applied_ops: Vec<StrictOperationKey>,
}

/// Disposable checkpoint of the derived per-channel ACL programs. The
/// server-scoped repository versions bind the complete program view to the
/// authoritative channel history without forcing unchanged programs to be
/// recompiled at every version.
#[derive(Serialize, Deserialize)]
struct EffectiveAclCacheSnapshot {
    format_version: u32,
    versions: HashMap<String, u64>,
    /// Fingerprints the authoritative ACL inputs, preventing an equal-version
    /// checkpoint from a different repository timeline from being accepted.
    state_fingerprints: HashMap<String, u64>,
    channels: Vec<EffectiveAclCacheChannel>,
}

#[derive(Serialize, Deserialize)]
struct EffectiveAclCacheChannel {
    server_id: String,
    channel_id: u32,
    program: crate::acl::CompiledEffectiveAcl,
}

// ─── ChannelRepository ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct CachedAclPermissions {
    channel_acl_generation: u64,
    client_acl_subject_generation: u64,
    client_acl_home_generation: u64,
    depends_on_home_channel: bool,
    explicit_enter_deny_overrides_write: bool,
    permissions: BitFlags<ACLPermissions>,
}

impl CachedAclPermissions {
    fn hit_for(
        &self,
        channel_acl_generation: u64,
        client_acl_subject_generation: u64,
        client_acl_home_generation: u64,
        explicit_enter_deny_overrides_write: bool,
    ) -> Option<AclCacheHit> {
        let cache_key_matches = self.channel_acl_generation == channel_acl_generation
            && self.client_acl_subject_generation == client_acl_subject_generation
            && (!self.depends_on_home_channel
                || self.client_acl_home_generation == client_acl_home_generation)
            && self.explicit_enter_deny_overrides_write == explicit_enter_deny_overrides_write;
        cache_key_matches.then_some(AclCacheHit {
            permissions: self.permissions,
            depends_on_home_channel: self.depends_on_home_channel,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AclCacheHit {
    permissions: BitFlags<ACLPermissions>,
    depends_on_home_channel: bool,
}

impl AclCacheHit {
    pub fn permissions(self) -> BitFlags<ACLPermissions> {
        self.permissions
    }

    pub fn depends_on_home_channel(self) -> bool {
        self.depends_on_home_channel
    }
}

fn ordered_channel_ids(channels: &ChannelMap) -> Arc<[u32]> {
    let mut children: HashMap<Option<u32>, Vec<u32>> = HashMap::new();
    for channel in channels.values() {
        children
            .entry(channel.parent_id)
            .or_default()
            .push(channel.id);
    }
    for child_ids in children.values_mut() {
        child_ids.sort_unstable_by_key(|id| {
            channels
                .get(id)
                .map(|channel| (channel.position, channel.id))
                .unwrap_or((0, *id))
        });
    }

    let mut ordered = Vec::with_capacity(channels.len());
    let mut visited = HashSet::with_capacity(channels.len());
    let mut queue = VecDeque::new();
    if channels.contains_key(&0) {
        queue.push_back(0);
    }

    while let Some(channel_id) = queue.pop_front() {
        if !visited.insert(channel_id) || !channels.contains_key(&channel_id) {
            continue;
        }
        ordered.push(channel_id);
        if let Some(child_ids) = children.get(&Some(channel_id)) {
            queue.extend(child_ids.iter().copied());
        }
    }

    let mut remaining: Vec<_> = channels
        .values()
        .filter(|channel| !visited.contains(&channel.id))
        .map(|channel| channel.id)
        .collect();
    remaining.sort_unstable_by_key(|id| {
        let channel = &channels[id];
        (channel.parent_id.unwrap_or(0), channel.position, channel.id)
    });
    ordered.extend(remaining);
    Arc::from(ordered.into_boxed_slice())
}

fn ordered_channels(channels: &ChannelMap) -> OrderedChannelSnapshot {
    let ordered_ids = ordered_channel_ids(channels);
    Arc::from(
        ordered_ids
            .iter()
            .filter_map(|channel_id| channels.get(channel_id).map(Arc::clone))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

fn rebuild_all_ordered_channel_views(
    channels_by_server: &ChannelsByServer,
) -> HashMap<String, OrderedChannelSnapshot> {
    channels_by_server
        .iter()
        .map(|(server_id, channels)| (server_id.clone(), ordered_channels(channels)))
        .collect()
}

/// A stable, operation-scoped view of a server's channel tree.
///
/// The repository's ordinary read helpers acquire the channel lock and rebuild
/// tree relationships for each call. Fan-out operations should create one of
/// these snapshots and share it across their workers instead: child adjacency
/// and ancestor chains are indexed once when the snapshot is created.
#[derive(Clone, Debug)]
pub struct ChannelTreeSnapshot {
    channels: Arc<ChannelMap>,
    ordered_channel_ids: Arc<[u32]>,
    children_by_parent: Arc<HashMap<u32, Arc<[u32]>>>,
    ancestor_ids_by_channel: Arc<HashMap<u32, Arc<[u32]>>>,
}

impl ChannelTreeSnapshot {
    fn new(channels: ChannelMap) -> Self {
        let ordered_channel_ids = ordered_channel_ids(&channels);
        Self::new_with_order(channels, ordered_channel_ids)
    }

    fn new_with_order(channels: ChannelMap, ordered_channel_ids: Arc<[u32]>) -> Self {
        let mut children_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
        for channel in channels.values() {
            if let Some(parent_id) = channel.parent_id {
                children_by_parent
                    .entry(parent_id)
                    .or_default()
                    .push(channel.id);
            }
        }
        for children in children_by_parent.values_mut() {
            children.sort_unstable();
        }
        let children_by_parent = children_by_parent
            .into_iter()
            .map(|(parent_id, children)| (parent_id, Arc::from(children.into_boxed_slice())))
            .collect();

        let ancestor_ids_by_channel = channels
            .keys()
            .copied()
            .map(|channel_id| {
                let mut ancestor_ids = Vec::new();
                let mut visited = HashSet::new();
                let mut current_id = channel_id;
                while visited.insert(current_id) {
                    let Some(parent_id) = channels
                        .get(&current_id)
                        .and_then(|channel| channel.parent_id)
                    else {
                        break;
                    };
                    if !channels.contains_key(&parent_id) {
                        break;
                    }
                    ancestor_ids.push(parent_id);
                    current_id = parent_id;
                }
                (channel_id, Arc::from(ancestor_ids.into_boxed_slice()))
            })
            .collect();

        Self {
            channels: Arc::new(channels),
            ordered_channel_ids,
            children_by_parent: Arc::new(children_by_parent),
            ancestor_ids_by_channel: Arc::new(ancestor_ids_by_channel),
        }
    }

    pub fn len(&self) -> usize {
        self.channels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    pub fn channel(&self, channel_id: u32) -> Option<&Channel> {
        self.channels.get(&channel_id).map(AsRef::as_ref)
    }

    pub fn channel_arc(&self, channel_id: u32) -> Option<&Arc<Channel>> {
        self.channels.get(&channel_id)
    }

    pub fn channels(&self) -> impl ExactSizeIterator<Item = &Channel> {
        self.channels.values().map(AsRef::as_ref)
    }

    pub fn channel_ids(&self) -> impl ExactSizeIterator<Item = u32> + '_ {
        self.channels.keys().copied()
    }

    /// Channels in root-first breadth-first order, with siblings ordered by
    /// position and id. Orphans and cycles follow in stable fallback order.
    pub fn ordered_channels(&self) -> impl ExactSizeIterator<Item = &Channel> {
        self.ordered_channel_ids
            .iter()
            .map(|channel_id| self.channels[channel_id].as_ref())
    }

    /// Return precomputed ancestor ids, from the immediate parent to root.
    pub fn ancestor_ids(&self, channel_id: u32) -> Option<&[u32]> {
        self.ancestor_ids_by_channel
            .get(&channel_id)
            .map(AsRef::as_ref)
    }

    /// Return `root_id` and its descendant ids in breadth-first order.
    ///
    /// Temporary channels are protocol leaves even if malformed legacy state
    /// contains children below one.
    pub fn subtree_ids(&self, root_id: u32) -> Vec<u32> {
        if self
            .channels
            .get(&root_id)
            .is_some_and(|channel| channel.is_temporary())
        {
            return vec![root_id];
        }

        let mut result = vec![root_id];
        let mut queue = VecDeque::from([root_id]);
        while let Some(channel_id) = queue.pop_front() {
            if let Some(children) = self.children_by_parent.get(&channel_id) {
                result.extend(children.iter().copied());
                queue.extend(children.iter().copied());
            }
        }
        result
    }

    /// Return the structural closure of multiple subtree roots in one walk.
    pub fn subtree_closure_ids(&self, root_ids: impl IntoIterator<Item = u32>) -> Vec<u32> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        for root_id in root_ids {
            if visited.insert(root_id) {
                result.push(root_id);
                queue.push_back(root_id);
            }
        }
        while let Some(channel_id) = queue.pop_front() {
            if self
                .channels
                .get(&channel_id)
                .is_some_and(|channel| channel.is_temporary())
            {
                continue;
            }
            let Some(children) = self.children_by_parent.get(&channel_id) else {
                continue;
            };
            for &child_id in children.iter() {
                if visited.insert(child_id) {
                    result.push(child_id);
                    queue.push_back(child_id);
                }
            }
        }
        result
    }

    /// Return the part of a subtree that still inherits ACLs from `root_id`.
    ///
    /// A channel with `inherit_acl = false` cuts off both itself and all of its
    /// descendants. This is useful after an operation has already determined
    /// that an inherited ACL property changed and does not need a conservative
    /// refresh of the entire structural subtree.
    pub fn inheriting_subtree_ids(&self, root_id: u32, include_root: bool) -> Vec<u32> {
        let mut result = include_root
            .then_some(root_id)
            .into_iter()
            .collect::<Vec<_>>();
        if self
            .channels
            .get(&root_id)
            .is_some_and(|channel| channel.is_temporary())
        {
            return result;
        }

        let mut queue = VecDeque::from([root_id]);
        while let Some(channel_id) = queue.pop_front() {
            let Some(children) = self.children_by_parent.get(&channel_id) else {
                continue;
            };
            for &child_id in children.iter() {
                if self
                    .channels
                    .get(&child_id)
                    .is_some_and(|channel| channel.inherit_acl)
                {
                    result.push(child_id);
                    queue.push_back(child_id);
                }
            }
        }
        result
    }

    /// Calculate the ACL cache/visibility scope using this stable tree view.
    pub fn acl_affected_channel_ids_for_op(&self, op: &ChannelOp) -> Option<HashSet<u32>> {
        match op {
            ChannelOp::CreateChannel { .. } => Some(HashSet::new()),
            ChannelOp::SetAcls { channel_id, .. } => {
                Some(self.subtree_ids(*channel_id).into_iter().collect())
            }
            ChannelOp::UpdateChannel { id, patch } | ChannelOp::EditChannel { id, patch, .. }
                if patch.parent_id.is_some() =>
            {
                let mut affected: HashSet<u32> = self.subtree_ids(*id).into_iter().collect();
                affected.extend(channels_with_home_channel_dependent_acls_with_children(
                    &self.channels,
                    &self.children_by_parent,
                ));
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
}

/// Transient context retained for one committed ACL replacement.
///
/// The operation itself remains the durable source of the new ACL state. This
/// hint supplies the old ACL state and a single indexed view of the resulting
/// tree so in-process consumers can calculate precise before/after deltas.
#[derive(Clone, Debug)]
pub struct AclChangeHint {
    channel_id: u32,
    impact: AclChangeImpact,
    old_inherit_acl: bool,
    old_acls: Arc<[ACL]>,
    affected_channel_ids: Arc<[u32]>,
    tree_snapshot: Arc<ChannelTreeSnapshot>,
}

impl AclChangeHint {
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    pub fn impact(&self) -> &AclChangeImpact {
        &self.impact
    }

    pub fn old_inherit_acl(&self) -> bool {
        self.old_inherit_acl
    }

    pub fn old_acls(&self) -> &[ACL] {
        &self.old_acls
    }

    /// Channels whose effective permissions may change directly from the ACL
    /// replacement: the edited channel for `apply_here`, plus inheriting
    /// descendants for `apply_subs`.
    ///
    /// This deliberately is not the structural visibility closure. A caller
    /// reconciling Traverse/Write visibility should expand an affected
    /// `apply_here` channel through [`ChannelTreeSnapshot::subtree_ids`] using
    /// [`Self::tree_snapshot`].
    pub fn affected_channel_ids(&self) -> &[u32] {
        &self.affected_channel_ids
    }

    /// The channel tree immediately after the operation was applied.
    pub fn tree_snapshot(&self) -> Arc<ChannelTreeSnapshot> {
        Arc::clone(&self.tree_snapshot)
    }
}

fn build_acl_change_hint(
    channels: &ChannelMap,
    channel_id: u32,
    old_inherit_acl: bool,
    old_acls: Vec<ACL>,
    new_inherit_acl: bool,
    new_acls: &[ACL],
) -> AclChangeHint {
    let impact = classify_acl_change(old_inherit_acl, &old_acls, new_inherit_acl, new_acls);
    if !impact.state_changed() {
        return AclChangeHint {
            channel_id,
            impact,
            old_inherit_acl,
            old_acls: Arc::from(old_acls.into_boxed_slice()),
            affected_channel_ids: Arc::from([]),
            tree_snapshot: Arc::new(ChannelTreeSnapshot::new(HashMap::new())),
        };
    }
    let tree_snapshot = Arc::new(ChannelTreeSnapshot::new(channels.clone()));
    let mut affected_channel_ids = Vec::new();
    if !impact.apply_here().is_empty() {
        if impact
            .apply_here()
            .effective_permissions()
            .contains(ACLPermissions::Traverse)
        {
            affected_channel_ids.extend(tree_snapshot.subtree_ids(channel_id));
        } else {
            affected_channel_ids.push(channel_id);
        }
    }
    if !impact.apply_subs().is_empty() {
        let inheriting_descendants = tree_snapshot.inheriting_subtree_ids(channel_id, false);
        if impact
            .apply_subs()
            .effective_permissions()
            .contains(ACLPermissions::Traverse)
        {
            affected_channel_ids.extend(tree_snapshot.subtree_closure_ids(inheriting_descendants));
        } else {
            affected_channel_ids.extend(inheriting_descendants);
        }
    }
    affected_channel_ids.sort_unstable();
    affected_channel_ids.dedup();

    AclChangeHint {
        channel_id,
        impact,
        old_inherit_acl,
        old_acls: Arc::from(old_acls.into_boxed_slice()),
        affected_channel_ids: Arc::from(affected_channel_ids.into_boxed_slice()),
        tree_snapshot,
    }
}

#[derive(Debug, Clone, Default)]
struct LinkTopology {
    groups_by_channel: HashMap<u32, Arc<[u32]>>,
}

impl LinkTopology {
    fn from_channels(channels: &ChannelMap) -> Self {
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

    fn remove_deleted_channels(&mut self, channels: &ChannelMap, deleted_ids: &[u32]) {
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
    channels: ParkingRwLock<ChannelsByServer>,
    /// Immutable root-first, position-ordered channel views derived from `channels`.
    /// Writers update this while holding the channel write guard; readers
    /// acquire the channel read guard before reading this index.
    ordered_channels: ParkingRwLock<HashMap<String, OrderedChannelSnapshot>>,
    /// Derived transitive link groups, rebuilt from direct channel links.
    link_topologies: ParkingRwLock<HashMap<String, LinkTopology>>,
    versions: ParkingRwLock<HashMap<String, u64>>,
    /// Strict operation ids committed through this repository.
    strict_applied_ops: ParkingRwLock<HashSet<StrictOperationKey>>,
    /// Serializes every state transition that can affect a replication
    /// snapshot. In particular, it keeps a strict operation's durable WAL
    /// record, in-memory state, and op-id ledger in one ordered transaction.
    strict_apply_lock: AsyncMutex<()>,
    /// In-memory log for `get_log_since` and future S2S queries.
    log: ParkingRwLock<std::collections::VecDeque<ChannelLogEntry>>,
    log_max_entries: usize,
    delete_visibility_hints: ParkingRwLock<HashMap<(String, u64), Arc<[u32]>>>,
    acl_change_hints: ParkingRwLock<HashMap<(String, u64), Arc<AclChangeHint>>>,
    /// Bumped whenever channel state can change effective ACL results.
    channel_acl_generation: AtomicU64,
    /// Per-channel ACL generations for targeted channel cache eviction.
    /// Per-server, per-channel ACL generations. Nesting by server lets the
    /// permission hot path borrow `&str` directly instead of allocating a new
    /// `String` for every cache validation.
    channel_acl_generations: ParkingRwLock<HashMap<String, HashMap<u32, u64>>>,
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
    /// A failed WAL sync has ambiguous durability: the record may already be
    /// persistent even though the OS returned an error. Do not append further
    /// records in this process; restart/recovery will reconcile the WAL.
    wal_poisoned: AtomicBool,
    #[cfg(test)]
    force_next_wal_sync_failure: AtomicBool,
    #[cfg(test)]
    force_next_snapshot_write_failure: AtomicBool,
    snapshot_every_ops: u64,
    snapshot_every_secs: i64,
    wal_compaction_expire_count: usize,
    /// Broadcast channel for S2S subscribers.
    tx: broadcast::Sender<Arc<ChannelOperation>>,
    observer: ParkingMutex<Option<Arc<dyn ChannelRepositoryObserver>>>,
    /// Unix timestamp when the last snapshot compaction succeeded.
    last_snapshot_at: AtomicI64,
    history_freshness: ParkingRwLock<HashMap<String, i64>>,
    /// Whether the versioned effective-ACL program view has advanced since
    /// its last successful periodic checkpoint.
    effective_acl_cache_dirty: AtomicBool,
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
            .insert(0, Arc::new(root_channel(&root_config)));
        rebuild_all_effective_acl_caches(&mut channels);
        let ordered_channels = rebuild_all_ordered_channel_views(&channels);
        let mut versions = HashMap::new();
        versions.insert(DEFAULT_SERVER_ID.to_owned(), 0);
        Arc::new(Self {
            node_id,
            root_config: ParkingRwLock::new(root_config),
            channels: ParkingRwLock::new(channels),
            ordered_channels: ParkingRwLock::new(ordered_channels),
            link_topologies: ParkingRwLock::new(HashMap::new()),
            versions: ParkingRwLock::new(versions),
            strict_applied_ops: ParkingRwLock::new(HashSet::new()),
            strict_apply_lock: AsyncMutex::new(()),
            log: ParkingRwLock::new(std::collections::VecDeque::new()),
            log_max_entries: tuning.log_max_entries,
            delete_visibility_hints: ParkingRwLock::new(HashMap::new()),
            acl_change_hints: ParkingRwLock::new(HashMap::new()),
            channel_acl_generation: AtomicU64::new(0),
            channel_acl_generations: ParkingRwLock::new(HashMap::new()),
            acl_cache: HashCache::new(),
            storage_dir: None,
            wal_file: None,
            wal_entry_count: AtomicUsize::new(0),
            wal_poisoned: AtomicBool::new(false),
            #[cfg(test)]
            force_next_wal_sync_failure: AtomicBool::new(false),
            #[cfg(test)]
            force_next_snapshot_write_failure: AtomicBool::new(false),
            snapshot_every_ops: tuning.snapshot_every_ops,
            snapshot_every_secs: tuning.snapshot_every_secs,
            wal_compaction_expire_count: tuning.wal_compaction_expire_count,
            tx,
            observer: ParkingMutex::new(None),
            last_snapshot_at: AtomicI64::new(chrono::Utc::now().timestamp()),
            history_freshness: ParkingRwLock::new(HashMap::new()),
            effective_acl_cache_dirty: AtomicBool::new(false),
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
        let (mut channels, mut versions, mut history_freshness, mut strict_applied_ops) =
            match tokio::fs::read(&snapshot_path).await {
                Ok(data) => {
                    let snap: Snapshot = serde_json::from_slice(&data).map_err(|e| {
                        ChannelRepoError::WalCorrupt {
                            line: 0,
                            reason: format!("snapshot corrupt: {e}"),
                        }
                    })?;
                    let mut map: ChannelsByServer = HashMap::new();
                    for scoped in snap.channels {
                        let channel = scoped.channel.into_channel(&root_config);
                        map.entry(scoped.server_id)
                            .or_default()
                            .insert(channel.id, Arc::new(channel));
                    }
                    let mut versions = snap.versions;
                    if versions.is_empty() {
                        versions.insert(DEFAULT_SERVER_ID.to_owned(), snap.version);
                    }
                    (
                        map,
                        versions,
                        snap.history_freshness,
                        snap.strict_applied_ops.into_iter().collect(),
                    )
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => (
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::new(),
                    HashSet::new(),
                ),
                Err(e) => return Err(ChannelRepoError::WalIo(e)),
            };

        let mut acl_cache_servers =
            load_effective_acl_cache_checkpoint(storage_dir, &versions, &mut channels).await;
        let mut effective_acl_cache_dirty = acl_cache_servers.len() != channels.len();

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
            if let Some(metadata) = strict_metadata.filter(|_| !record.strict_id_owned_by_s2s) {
                strict_applied_ops.insert(StrictOperationKey::new(&op.server_id, metadata));
            }
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
            if acl_cache_servers.contains(&op.server_id)
                && op.version != base_version.saturating_add(1)
            {
                // The program checkpoint cannot be advanced safely across a
                // missing repository operation. Rebuild this server once from
                // final authoritative state after replay instead.
                acl_cache_servers.remove(&op.server_id);
            }
            let scoped_channels = channels.entry(op.server_id.clone()).or_default();
            ensure_root_channel(scoped_channels, &root_config);
            apply_op_to_map(scoped_channels, &op.op, op.node_id, &root_config);
            if acl_cache_servers.contains(&op.server_id) {
                rebuild_effective_acl_caches_for_op(scoped_channels, &op.op);
            }
            effective_acl_cache_dirty = true;
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
        acl_cache_servers.retain(|server_id| {
            channels
                .get(server_id)
                .is_some_and(effective_acl_caches_are_complete)
        });
        for (server_id, scoped_channels) in &mut channels {
            if !acl_cache_servers.contains(server_id) {
                rebuild_all_effective_acl_caches_in_map(scoped_channels);
                effective_acl_cache_dirty = true;
            }
        }
        versions.entry(DEFAULT_SERVER_ID.to_owned()).or_insert(0);
        let link_topologies = rebuild_all_link_topologies(&mut channels);
        let ordered_channels = rebuild_all_ordered_channel_views(&channels);

        let (tx, _) = broadcast::channel(256);

        Ok(Arc::new(Self {
            node_id,
            root_config: ParkingRwLock::new(root_config),
            channels: ParkingRwLock::new(channels),
            ordered_channels: ParkingRwLock::new(ordered_channels),
            link_topologies: ParkingRwLock::new(link_topologies),
            versions: ParkingRwLock::new(versions),
            strict_applied_ops: ParkingRwLock::new(strict_applied_ops),
            strict_apply_lock: AsyncMutex::new(()),
            log: ParkingRwLock::new(log_entries),
            log_max_entries: tuning.log_max_entries,
            delete_visibility_hints: ParkingRwLock::new(HashMap::new()),
            acl_change_hints: ParkingRwLock::new(HashMap::new()),
            channel_acl_generation: AtomicU64::new(0),
            channel_acl_generations: ParkingRwLock::new(HashMap::new()),
            acl_cache: HashCache::new(),
            storage_dir: Some(storage_dir.to_owned()),
            wal_file: Some(AsyncMutex::new(wal_file)),
            wal_entry_count: AtomicUsize::new(wal_entry_count),
            wal_poisoned: AtomicBool::new(false),
            #[cfg(test)]
            force_next_wal_sync_failure: AtomicBool::new(false),
            #[cfg(test)]
            force_next_snapshot_write_failure: AtomicBool::new(false),
            snapshot_every_ops: tuning.snapshot_every_ops,
            snapshot_every_secs: tuning.snapshot_every_secs,
            wal_compaction_expire_count: tuning.wal_compaction_expire_count,
            tx,
            observer: ParkingMutex::new(None),
            last_snapshot_at: AtomicI64::new(chrono::Utc::now().timestamp()),
            history_freshness: ParkingRwLock::new(history_freshness),
            effective_acl_cache_dirty: AtomicBool::new(effective_acl_cache_dirty),
        }))
    }

    // ── Version ───────────────────────────────────────────────────────────

    pub fn current_version(&self) -> u64 {
        self.current_version_in_server(DEFAULT_SERVER_ID)
    }

    pub fn current_version_in_server(&self, server_id: &str) -> u64 {
        self.versions.read().get(server_id).copied().unwrap_or(0)
    }

    /// Whether strict operation ids are backed by restart-safe repository
    /// storage. A poisoned WAL fails closed because its final sync outcome is
    /// ambiguous until startup recovery reloads it.
    pub fn strict_operation_durability_enabled(&self) -> bool {
        self.storage_dir.is_some() && !self.wal_poisoned.load(Ordering::Acquire)
    }

    /// Return the durable strict operation ids for the default channel scope.
    pub fn strict_operation_ids(&self) -> Vec<StrictOperationId> {
        self.strict_operation_ids_in_server(DEFAULT_SERVER_ID)
    }

    /// Return the durable strict operation ids for one channel scope. These
    /// ids are intended to accompany an S2S channel snapshot.
    pub fn strict_operation_ids_in_server(&self, server_id: &str) -> Vec<StrictOperationId> {
        let mut operation_ids: Vec<_> = self
            .strict_applied_ops
            .read()
            .iter()
            .filter(|key| key.server_id == server_id)
            .map(|key| key.operation_id.clone())
            .collect();
        operation_ids.sort_unstable_by(|left, right| {
            (left.op_id_hi, left.op_id_lo).cmp(&(right.op_id_hi, right.op_id_lo))
        });
        operation_ids
    }

    /// Capture channel state and its strict-replication idempotency ledger at
    /// one write-transaction boundary. This is the only snapshot API that
    /// v1 strict replication should use.
    pub async fn strict_snapshot_in_server(&self, server_id: &str) -> ChannelStrictSnapshot {
        let _write_transaction = self.strict_apply_lock.lock().await;
        let root_config = self.root_config.read().clone();
        let all_channels = self.channels.read();
        let channels = all_channels
            .get(server_id)
            .map(|channels| {
                self.ordered_channel_view_in_server(server_id, channels)
                    .as_ref()
                    .iter()
                    .map(|channel| channel.as_ref().clone())
                    .collect()
            })
            .unwrap_or_else(|| vec![root_channel(&root_config)]);
        let version = self.versions.read().get(server_id).copied().unwrap_or(0);
        let freshness = self
            .history_freshness
            .read()
            .get(server_id)
            .copied()
            .unwrap_or(0);
        let operation_ids = self.strict_operation_ids_in_server(server_id);

        ChannelStrictSnapshot {
            version,
            channels,
            freshness,
            operation_ids,
        }
    }

    /// Capture an atomic S2S repository snapshot. The frozen legacy ledger is
    /// included only for rolling compatibility with pre-v5 receivers; new v5
    /// applications no longer add entries to it.
    pub async fn s2s_snapshot_in_server(&self, server_id: &str) -> ChannelStrictSnapshot {
        let _write_transaction = self.strict_apply_lock.lock().await;
        let root_config = self.root_config.read().clone();
        let all_channels = self.channels.read();
        let channels = all_channels
            .get(server_id)
            .map(|channels| {
                self.ordered_channel_view_in_server(server_id, channels)
                    .as_ref()
                    .iter()
                    .map(|channel| channel.as_ref().clone())
                    .collect()
            })
            .unwrap_or_else(|| vec![root_channel(&root_config)]);
        let version = self.versions.read().get(server_id).copied().unwrap_or(0);
        let freshness = self
            .history_freshness
            .read()
            .get(server_id)
            .copied()
            .unwrap_or(0);

        let operation_ids = self.strict_operation_ids_in_server(server_id);
        ChannelStrictSnapshot {
            version,
            channels,
            freshness,
            operation_ids,
        }
    }

    /// Merge strict operation ids received with a snapshot for the default
    /// channel scope and persist the expanded ledger.
    pub async fn merge_strict_operation_ids(
        self: &Arc<Self>,
        operation_ids: Vec<StrictOperationId>,
    ) -> Result<(), ChannelRepoError> {
        self.merge_strict_operation_ids_in_server(DEFAULT_SERVER_ID, operation_ids)
            .await
    }

    /// Merge strict operation ids received with a snapshot for one channel
    /// scope and persist the expanded ledger.
    pub async fn merge_strict_operation_ids_in_server(
        self: &Arc<Self>,
        server_id: &str,
        operation_ids: Vec<StrictOperationId>,
    ) -> Result<(), ChannelRepoError> {
        let _strict_apply_guard = self.strict_apply_lock.lock().await;
        self.persist_strict_operation_ids_candidate(server_id, &operation_ids)
            .await?;
        self.merge_strict_operation_ids_in_server_unpersisted(server_id, operation_ids);
        Ok(())
    }

    /// Make an op-id ledger expansion durable before exposing it in memory.
    /// The write transaction is held by the caller.
    async fn persist_strict_operation_ids_candidate(
        &self,
        server_id: &str,
        operation_ids: &[StrictOperationId],
    ) -> Result<(), ChannelRepoError> {
        if self.storage_dir.is_none() {
            return Ok(());
        }

        let mut applied_operations = self.strict_applied_ops.read().clone();
        applied_operations.extend(
            operation_ids
                .iter()
                .cloned()
                .map(|operation_id| StrictOperationKey::with_operation_id(server_id, operation_id)),
        );
        let snapshot = self.snapshot_from_state(
            self.versions.read().clone(),
            self.history_freshness.read().clone(),
            applied_operations,
            self.channels.read().clone(),
        );
        self.write_strict_snapshot_candidate(&snapshot).await
    }

    fn merge_strict_operation_ids_in_server_unpersisted(
        &self,
        server_id: &str,
        operation_ids: Vec<StrictOperationId>,
    ) {
        let mut applied_ops = self.strict_applied_ops.write();
        applied_ops.extend(
            operation_ids
                .into_iter()
                .map(|operation_id| StrictOperationKey::with_operation_id(server_id, operation_id)),
        );
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
                    .get(server_id)
                    .and_then(|generations| generations.get(&channel_id))
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
        let generations = generations.entry(server_id.to_owned()).or_default();
        for channel_id in channel_ids {
            generations
                .entry(*channel_id)
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

    fn ensure_ordered_channel_view_in_server(&self, server_id: &str, channels: &ChannelMap) {
        if self.ordered_channels.read().contains_key(server_id) {
            return;
        }
        self.rebuild_ordered_channel_view_in_server(server_id, channels);
    }

    fn rebuild_ordered_channel_view_in_server(&self, server_id: &str, channels: &ChannelMap) {
        self.ordered_channels
            .write()
            .insert(server_id.to_owned(), ordered_channels(channels));
    }

    fn ordered_channel_view_in_server(
        &self,
        server_id: &str,
        channels: &ChannelMap,
    ) -> OrderedChannelSnapshot {
        if !channels.contains_key(&0) {
            let mut with_root = channels.clone();
            with_root.insert(0, Arc::new(self.root_channel()));
            return ordered_channels(&with_root);
        }
        let ordered = self
            .ordered_channels
            .read()
            .get(server_id)
            .cloned()
            .unwrap_or_else(|| ordered_channels(channels));
        debug_assert_eq!(ordered.len(), channels.len());
        ordered
    }

    pub async fn update_root_channel_config(&self, root_config: ChannelRootConfig) {
        let _write_transaction = self.strict_apply_lock.lock().await;
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
                    Arc::make_mut(root).name = root_config.name().to_owned();
                }
                self.rebuild_ordered_channel_view_in_server(server_id, channels);
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

    pub async fn get_channel(&self, id: u32) -> Option<Arc<Channel>> {
        self.get_channel_in_server(DEFAULT_SERVER_ID, id).await
    }

    pub async fn get_channel_in_server(&self, server_id: &str, id: u32) -> Option<Arc<Channel>> {
        self.channels
            .read()
            .get(server_id)
            .and_then(|channels| channels.get(&id))
            .cloned()
            .or_else(|| (id == 0).then(|| Arc::new(self.root_channel())))
    }

    /// Clone one stable server channel tree and build its reusable indexes.
    ///
    /// Callers handling one operation for many clients should create this once
    /// and share the returned snapshot rather than repeatedly querying the
    /// repository for subtrees and ancestor chains.
    pub fn channel_tree_snapshot_in_server(&self, server_id: &str) -> ChannelTreeSnapshot {
        let root = self.root_channel();
        let all_channels = self.channels.read();
        let mut channels = all_channels.get(server_id).cloned().unwrap_or_default();
        channels.entry(0).or_insert_with(|| Arc::new(root));
        let ordered_ids = self
            .ordered_channels
            .read()
            .get(server_id)
            .filter(|ordered| {
                ordered.len() == channels.len()
                    && ordered
                        .iter()
                        .all(|channel| channels.contains_key(&channel.id))
            })
            .map(|ordered| {
                Arc::from(
                    ordered
                        .iter()
                        .map(|channel| channel.id)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                )
            })
            .unwrap_or_else(|| ordered_channel_ids(&channels));
        ChannelTreeSnapshot::new_with_order(channels, ordered_ids)
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

    /// Return transient before/after context for a retained ACL operation.
    ///
    /// Matching by server and committed version makes this safe for replayed
    /// operation values without attaching process-local data to the WAL type.
    pub fn acl_change_hint_for_operation(
        &self,
        op: &ChannelOperation,
    ) -> Option<Arc<AclChangeHint>> {
        if !matches!(op.op, ChannelOp::SetAcls { .. }) {
            return None;
        }
        self.acl_change_hints
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

    pub async fn get_all(&self) -> Vec<Arc<Channel>> {
        self.get_all_in_server(DEFAULT_SERVER_ID).await
    }

    pub async fn get_all_in_server(&self, server_id: &str) -> Vec<Arc<Channel>> {
        self.ordered_snapshot_in_server(server_id).as_ref().to_vec()
    }

    /// Return the immutable, maintained root-first channel view for one scope.
    pub fn ordered_snapshot_in_server(&self, server_id: &str) -> OrderedChannelSnapshot {
        let channels = self.channels.read();
        match channels.get(server_id) {
            Some(channels) => self.ordered_channel_view_in_server(server_id, channels),
            None => Arc::from(vec![Arc::new(self.root_channel())].into_boxed_slice()),
        }
    }

    /// Capture a channel tree and its committed version under the repository's
    /// write-transaction fence. This avoids pairing a version reserved by an
    /// in-flight operation with the state from before that operation.
    pub async fn ordered_snapshot_with_version_in_server(
        &self,
        server_id: &str,
    ) -> (OrderedChannelSnapshot, u64) {
        let _write_transaction = self.strict_apply_lock.lock().await;
        let channels = self.channels.read();
        let version = self.versions.read().get(server_id).copied().unwrap_or(0);
        let channels = match channels.get(server_id) {
            Some(channels) => self.ordered_channel_view_in_server(server_id, channels),
            None => Arc::from(vec![Arc::new(self.root_channel())].into_boxed_slice()),
        };
        (channels, version)
    }

    pub fn snapshot_with_version_and_subscription_in_server(
        &self,
        server_id: &str,
    ) -> (OrderedChannelSnapshot, u64, ChannelStateSubscription) {
        let channels = self.channels.read();
        let version = self.versions.read().get(server_id).copied().unwrap_or(0);
        let rx = self.tx.subscribe();
        let channels = match channels.get(server_id) {
            Some(channels) => self.ordered_channel_view_in_server(server_id, channels),
            None => Arc::from(vec![Arc::new(self.root_channel())].into_boxed_slice()),
        };
        (channels, version, rx)
    }

    /// Capture a committed channel tree, its version, and a subscription that
    /// receives every operation committed after that capture.
    pub async fn ordered_snapshot_with_version_and_subscription_in_server(
        &self,
        server_id: &str,
    ) -> (OrderedChannelSnapshot, u64, ChannelStateSubscription) {
        let _write_transaction = self.strict_apply_lock.lock().await;
        self.snapshot_with_version_and_subscription_in_server(server_id)
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

    pub async fn get_children(&self, parent_id: u32) -> Vec<Arc<Channel>> {
        self.get_children_in_server(DEFAULT_SERVER_ID, parent_id)
            .await
    }

    pub async fn get_children_in_server(
        &self,
        server_id: &str,
        parent_id: u32,
    ) -> Vec<Arc<Channel>> {
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

    pub async fn get_all_scoped(&self) -> Vec<(String, Arc<Channel>)> {
        self.channels
            .read()
            .iter()
            .flat_map(|(server_id, channels)| {
                channels
                    .values()
                    .map(|channel| (server_id.clone(), Arc::clone(channel)))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn known_server_ids(&self) -> Vec<String> {
        self.channels.read().keys().cloned().collect()
    }

    /// Returns the chain of ancestors for `channel_id`, starting from the
    /// immediate parent up to (and including) the root.
    pub async fn get_ancestors(&self, channel_id: u32) -> Vec<Arc<Channel>> {
        self.get_ancestors_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn get_ancestors_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> Vec<Arc<Channel>> {
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
            result.push(Arc::clone(parent));
            current_id = pid;
        }
        result
    }

    /// Return both a channel and its ancestor chain in a single lock
    /// acquisition.  Avoids the double-lock pattern in ACL evaluation.
    pub async fn get_channel_with_ancestors(
        &self,
        channel_id: u32,
    ) -> (Option<Arc<Channel>>, Vec<Arc<Channel>>) {
        self.get_channel_with_ancestors_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn get_channel_with_ancestors_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> (Option<Arc<Channel>>, Vec<Arc<Channel>>) {
        let channels = self.channels.read();
        let Some(channels) = channels.get(server_id) else {
            return if channel_id == 0 {
                (Some(Arc::new(self.root_channel())), Vec::new())
            } else {
                (None, Vec::new())
            };
        };
        let channel = channels
            .get(&channel_id)
            .cloned()
            .or_else(|| (channel_id == 0).then(|| Arc::new(self.root_channel())));
        let mut ancestors = Vec::new();
        let mut current_id = channel_id;
        loop {
            let Some(ch) = channels
                .get(&current_id)
                .cloned()
                .or_else(|| (current_id == 0).then(|| Arc::new(self.root_channel())))
            else {
                break;
            };
            let Some(pid) = ch.parent_id else { break };
            let Some(parent) = channels
                .get(&pid)
                .cloned()
                .or_else(|| (pid == 0).then(|| Arc::new(self.root_channel())))
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
    ) -> (u64, Option<Arc<Channel>>, Vec<Arc<Channel>>) {
        self.get_channel_with_ancestors_for_acl_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn get_channel_with_ancestors_for_acl_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> (u64, Option<Arc<Channel>>, Vec<Arc<Channel>>) {
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

    /// Return a prepared channel from a stable ACL generation snapshot.
    ///
    /// Repository channels carry a compiled effective ACL program, so the
    /// permission hot path normally does not need to clone their ancestors.
    pub async fn get_channel_for_acl_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> (u64, Option<Arc<Channel>>) {
        loop {
            let generation = self.channel_acl_generation_for_channel(server_id, channel_id);
            let channel = self.get_channel_in_server(server_id, channel_id).await;
            if self.channel_acl_generation_for_channel(server_id, channel_id) == generation {
                return (generation, channel);
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
    ) -> Result<Arc<Channel>, ChannelRepoError> {
        self.create_channel_in_server(DEFAULT_SERVER_ID, channel)
            .await
    }

    pub async fn create_channel_in_server(
        self: &Arc<Self>,
        server_id: &str,
        mut channel: Channel,
    ) -> Result<Arc<Channel>, ChannelRepoError> {
        let _write_transaction = self.strict_apply_lock.lock().await;
        let (op, created) = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);

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
            channels.insert(channel.id, Arc::new(channel.clone()));
            rebuild_effective_acl_caches_for_subtree(channels, channel.id);
            self.rebuild_ordered_channel_view_in_server(server_id, channels);
            if !channel.links.is_empty() {
                let mut link_topologies = self.link_topologies.write();
                sync_link_topology_for_server(&mut link_topologies, server_id, channels);
            }
            (op, Arc::clone(&channels[&channel.id]))
        };

        self.commit(op).await?;
        Ok(created)
    }

    pub async fn update_channel(
        self: &Arc<Self>,
        id: u32,
        patch: ChannelPatch,
    ) -> Result<Arc<Channel>, ChannelRepoError> {
        self.update_channel_in_server(DEFAULT_SERVER_ID, id, patch)
            .await
    }

    pub async fn update_channel_in_server(
        self: &Arc<Self>,
        server_id: &str,
        id: u32,
        patch: ChannelPatch,
    ) -> Result<Arc<Channel>, ChannelRepoError> {
        let _write_transaction = self.strict_apply_lock.lock().await;
        let parent_changed = patch.parent_id.is_some();
        let patch = self.normalize_patch_for_channel(id, patch);
        let (op, updated) = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);

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
            apply_patch(Arc::make_mut(channels.get_mut(&id).unwrap()), &patch);
            if parent_changed {
                rebuild_effective_acl_caches_for_subtree(channels, id);
            }
            self.rebuild_ordered_channel_view_in_server(server_id, channels);
            let updated = Arc::clone(&channels[&id]);
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
    ) -> Result<Arc<Channel>, ChannelRepoError> {
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
    ) -> Result<Arc<Channel>, ChannelRepoError> {
        let _write_transaction = self.strict_apply_lock.lock().await;
        let parent_changed = patch.parent_id.is_some();
        let patch = self.normalize_patch_for_channel(id, patch);
        let links_changed = !links_add.is_empty() || !links_remove.is_empty();
        let updated = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);

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
                Arc::make_mut(channels.get_mut(&id).unwrap())
                    .links
                    .insert(link_add);
                if let Some(target) = channels.get_mut(&link_add) {
                    Arc::make_mut(target).links.insert(id);
                }
            }

            for &link_remove in &links_remove {
                Arc::make_mut(channels.get_mut(&id).unwrap())
                    .links
                    .remove(&link_remove);
                if let Some(target) = channels.get_mut(&link_remove) {
                    Arc::make_mut(target).links.remove(&id);
                }
            }

            apply_patch(Arc::make_mut(channels.get_mut(&id).unwrap()), &patch);
            if parent_changed {
                rebuild_effective_acl_caches_for_subtree(channels, id);
            }
            self.rebuild_ordered_channel_view_in_server(server_id, channels);
            if links_changed {
                let mut link_topologies = self.link_topologies.write();
                sync_link_topology_for_server(&mut link_topologies, server_id, channels);
            }
            Arc::clone(&channels[&id])
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
        let _write_transaction = self.strict_apply_lock.lock().await;
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }
        let to_delete = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);
            if !channels.contains_key(&id) {
                return Err(ChannelRepoError::NotFound(id));
            }
            let to_delete = collect_subtree(&channels, id);
            let started_at_ms = chrono::Utc::now().timestamp_millis();
            for del_id in &to_delete {
                if let Some(ch) = channels.get_mut(del_id) {
                    Arc::make_mut(ch).pending_delete = Some(PendingDeleteState {
                        nonce,
                        started_at_ms,
                        origin_node: self.node_id,
                    });
                }
            }
            self.rebuild_ordered_channel_view_in_server(server_id, channels);
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
        let _write_transaction = self.strict_apply_lock.lock().await;
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }
        let applied_delete = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);
            if !channels.contains_key(&id) {
                return Err(ChannelRepoError::NotFound(id));
            };
            let applied_delete = apply_delete_channel_to_map(channels, id, nonce);
            if let Some(applied_delete) = &applied_delete {
                self.rebuild_ordered_channel_view_in_server(server_id, channels);
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
        if deleted {
            let valid_channel_ids = self
                .ordered_snapshot_in_server(server_id)
                .iter()
                .map(|channel| channel.id)
                .collect();
            let channel_version = self.current_version_in_server(server_id);
            self.move_local_clients_out_of_missing_channels_in_server(
                server_id,
                &valid_channel_ids,
                channel_version,
            )
            .await;
        }
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
        let _write_transaction = self.strict_apply_lock.lock().await;
        if id == 0 {
            return Err(ChannelRepoError::CannotDeleteRoot);
        }
        {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);
            let to_cancel = collect_subtree(&channels, id);
            for cancel_id in &to_cancel {
                if let Some(ch) = channels.get_mut(cancel_id) {
                    if ch
                        .pending_delete
                        .as_ref()
                        .is_some_and(|pending| pending.nonce == nonce)
                    {
                        Arc::make_mut(ch).pending_delete = None;
                    }
                }
            }
            self.rebuild_ordered_channel_view_in_server(server_id, channels);
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
        let _write_transaction = self.strict_apply_lock.lock().await;
        if a == b {
            return Ok(()); // no-op; callers should reject same-channel links
        }
        {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);
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
            Arc::make_mut(channels.get_mut(&a).unwrap()).links.insert(b);
            Arc::make_mut(channels.get_mut(&b).unwrap()).links.insert(a);
            self.rebuild_ordered_channel_view_in_server(server_id, channels);
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
        let _write_transaction = self.strict_apply_lock.lock().await;
        {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);
            if let Some(ch) = channels.get_mut(&a) {
                Arc::make_mut(ch).links.remove(&b);
            }
            if let Some(ch) = channels.get_mut(&b) {
                Arc::make_mut(ch).links.remove(&a);
            }
            self.rebuild_ordered_channel_view_in_server(server_id, channels);
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
        self.set_acls_if_changed(channel_id, inherit_acl, acls)
            .await
            .map(drop)
    }

    /// Set a channel's ACLs, returning whether the stored ACL state changed.
    pub async fn set_acls_if_changed(
        self: &Arc<Self>,
        channel_id: u32,
        inherit_acl: bool,
        acls: Vec<ACL>,
    ) -> Result<bool, ChannelRepoError> {
        self.set_acls_if_changed_in_server(DEFAULT_SERVER_ID, channel_id, inherit_acl, acls)
            .await
    }

    pub async fn set_acls_in_server(
        self: &Arc<Self>,
        server_id: &str,
        channel_id: u32,
        inherit_acl: bool,
        acls: Vec<ACL>,
    ) -> Result<(), ChannelRepoError> {
        self.set_acls_if_changed_in_server(server_id, channel_id, inherit_acl, acls)
            .await
            .map(drop)
    }

    /// Set a channel's ACLs, returning whether the stored ACL state changed.
    pub async fn set_acls_if_changed_in_server(
        self: &Arc<Self>,
        server_id: &str,
        channel_id: u32,
        inherit_acl: bool,
        acls: Vec<ACL>,
    ) -> Result<bool, ChannelRepoError> {
        self.set_acls_with_committed_operation_if_changed_in_server(
            server_id,
            channel_id,
            inherit_acl,
            acls,
        )
        .await
        .map(|operation| operation.is_some())
    }

    /// Set a channel's ACLs and return the exact committed operation when the
    /// stored ACL state changed.
    pub async fn set_acls_with_committed_operation_if_changed_in_server(
        self: &Arc<Self>,
        server_id: &str,
        channel_id: u32,
        inherit_acl: bool,
        acls: Vec<ACL>,
    ) -> Result<Option<Arc<ChannelOperation>>, ChannelRepoError> {
        let _write_transaction = self.strict_apply_lock.lock().await;
        let acl_change_hint = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.to_owned()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(server_id, channels);
            let ch = channels
                .get_mut(&channel_id)
                .ok_or(ChannelRepoError::NotFound(channel_id))?;
            if ch.inherit_acl == inherit_acl && ch.acls == acls {
                return Ok(None);
            }
            let old_inherit_acl = ch.inherit_acl;
            let old_acls = ch.acls.clone();
            let ch = Arc::make_mut(ch);
            ch.inherit_acl = inherit_acl;
            ch.acls = acls.clone();
            rebuild_effective_acl_caches_for_subtree(channels, channel_id);
            self.rebuild_ordered_channel_view_in_server(server_id, channels);
            build_acl_change_hint(
                channels,
                channel_id,
                old_inherit_acl,
                old_acls,
                inherit_acl,
                &acls,
            )
        };

        let op = self.make_op_in_server(
            server_id,
            ChannelOp::SetAcls {
                channel_id,
                inherit_acl,
                acls,
            },
        );
        if !acl_change_hint.affected_channel_ids.is_empty() {
            self.invalidate_acl_cache_for_op_scope(
                server_id,
                acl_change_hint
                    .affected_channel_ids
                    .iter()
                    .copied()
                    .collect(),
            );
        }
        let committed = self
            .commit_with_acl_change_hint(op, acl_change_hint)
            .await?;
        Ok(Some(committed))
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
        self.get_cached_permissions_in_server_with_generations(
            server_id,
            session_id,
            client_instance_id,
            channel_id,
            channel_acl_generation,
            client_acl_generation,
            client_acl_generation,
            explicit_enter_deny_overrides_write,
        )
        .await
        .map(AclCacheHit::permissions)
    }

    pub async fn get_cached_permissions_in_server_with_generations(
        &self,
        server_id: &str,
        session_id: u64,
        client_instance_id: u64,
        channel_id: u32,
        channel_acl_generation: u64,
        client_acl_subject_generation: u64,
        client_acl_home_generation: u64,
        explicit_enter_deny_overrides_write: bool,
    ) -> Option<AclCacheHit> {
        self.acl_cache
            .get_sync(&(
                server_id.to_owned(),
                session_id,
                client_instance_id,
                channel_id,
            ))
            .and_then(|entry| {
                entry.hit_for(
                    channel_acl_generation,
                    client_acl_subject_generation,
                    client_acl_home_generation,
                    explicit_enter_deny_overrides_write,
                )
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
        self.cache_permissions_in_server_with_generations(
            server_id,
            session_id,
            client_instance_id,
            channel_id,
            channel_acl_generation,
            client_acl_generation,
            client_acl_generation,
            true,
            explicit_enter_deny_overrides_write,
            permissions,
        )
        .await;
    }

    pub async fn cache_permissions_in_server_with_generations(
        &self,
        server_id: &str,
        session_id: u64,
        client_instance_id: u64,
        channel_id: u32,
        channel_acl_generation: u64,
        client_acl_subject_generation: u64,
        client_acl_home_generation: u64,
        depends_on_home_channel: bool,
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
                client_acl_subject_generation,
                client_acl_home_generation,
                depends_on_home_channel,
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
        let _strict_apply_guard = self.strict_apply_lock.lock().await;
        self.save_snapshot_inner().await
    }

    fn snapshot_from_state(
        &self,
        versions: HashMap<String, u64>,
        history_freshness: HashMap<String, i64>,
        strict_applied_ops: HashSet<StrictOperationKey>,
        channels_by_server: ChannelsByServer,
    ) -> Snapshot {
        let version = versions.get(DEFAULT_SERVER_ID).copied().unwrap_or_default();
        let mut strict_applied_ops: Vec<_> = strict_applied_ops.into_iter().collect();
        strict_applied_ops.sort_unstable_by(|left, right| {
            (
                &left.server_id,
                left.operation_id.op_id_hi,
                left.operation_id.op_id_lo,
            )
                .cmp(&(
                    &right.server_id,
                    right.operation_id.op_id_hi,
                    right.operation_id.op_id_lo,
                ))
        });
        let channels = channels_by_server
            .into_iter()
            .flat_map(|(server_id, channels)| {
                channels
                    .into_values()
                    .map(|channel| SnapshotChannel {
                        server_id: server_id.clone(),
                        channel: ChannelSnapshotState::from_channel(&channel),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        Snapshot {
            version,
            versions,
            history_freshness,
            saved_at: chrono::Utc::now().timestamp(),
            node_id: self.node_id,
            channels,
            strict_applied_ops,
        }
    }

    async fn write_snapshot_atomically(&self, snapshot: &Snapshot) -> Result<(), ChannelRepoError> {
        let Some(dir) = self.storage_dir.as_ref() else {
            return Ok(());
        };
        #[cfg(test)]
        if self
            .force_next_snapshot_write_failure
            .swap(false, Ordering::AcqRel)
        {
            return Err(ChannelRepoError::WalIo(io::Error::new(
                io::ErrorKind::Other,
                "forced channel snapshot write failure",
            )));
        }
        let snapshot_path = dir.join("channels.snapshot.json");
        let snapshot_tmp = dir.join("channels.snapshot.json.tmp");
        let json = serde_json::to_vec(snapshot).map_err(|e| ChannelRepoError::WalCorrupt {
            line: 0,
            reason: format!("snapshot serialisation error: {e}"),
        })?;

        {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&snapshot_tmp)
                .await?;
            file.write_all(&json).await?;
            file.sync_data().await?;
        }
        #[cfg(windows)]
        replace_file_atomically(&snapshot_tmp, &snapshot_path)?;
        #[cfg(not(windows))]
        tokio::fs::rename(&snapshot_tmp, &snapshot_path).await?;
        if let Some(parent) = snapshot_path.parent() {
            sync_parent_directory(parent)?;
        }
        self.last_snapshot_at
            .store(chrono::Utc::now().timestamp(), Ordering::Release);
        Ok(())
    }

    /// Caller must hold `strict_apply_lock` when a strict operation may be
    /// in flight, so a compacted snapshot cannot omit its durable op-id.
    async fn save_snapshot_inner(&self) -> Result<(), ChannelRepoError> {
        let Some(ref dir) = self.storage_dir else {
            return Ok(());
        };
        let wal_path = dir.join("channels.wal.jsonl");
        let wal_tmp = dir.join("channels.wal.jsonl.tmp");

        let versions = self.versions.read().clone();
        let history_freshness = self.history_freshness.read().clone();
        let strict_applied_ops = self.strict_applied_ops.read().clone();
        let channels_by_server = self.channels.read().clone();
        let effective_acl_cache_snapshot = self
            .effective_acl_cache_dirty
            .load(Ordering::Acquire)
            .then(|| effective_acl_cache_snapshot(&versions, &channels_by_server));
        let snapshot = self.snapshot_from_state(
            versions,
            history_freshness,
            strict_applied_ops,
            channels_by_server,
        );
        self.write_snapshot_atomically(&snapshot).await?;
        if let Some(effective_acl_cache_snapshot) = effective_acl_cache_snapshot {
            self.write_effective_acl_cache_atomically(&effective_acl_cache_snapshot)
                .await?;
            self.effective_acl_cache_dirty
                .store(false, Ordering::Release);
        }

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

                #[cfg(windows)]
                replace_file_atomically(&wal_tmp, &wal_path)?;
                #[cfg(not(windows))]
                tokio::fs::rename(&wal_tmp, &wal_path).await?;
                *wal = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&wal_path)
                    .await?;
                self.wal_entry_count.store(kept, Ordering::Release);
            }
        }

        Ok(())
    }

    async fn write_effective_acl_cache_atomically(
        &self,
        snapshot: &EffectiveAclCacheSnapshot,
    ) -> Result<(), ChannelRepoError> {
        let Some(dir) = self.storage_dir.as_ref() else {
            return Ok(());
        };
        let path = dir.join("channels.effective-acl-cache.json");
        let tmp = dir.join("channels.effective-acl-cache.json.tmp");
        let json = serde_json::to_vec(snapshot).map_err(|e| ChannelRepoError::WalCorrupt {
            line: 0,
            reason: format!("effective ACL cache serialisation error: {e}"),
        })?;
        {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .await?;
            file.write_all(&json).await?;
            file.sync_data().await?;
        }
        #[cfg(windows)]
        replace_file_atomically(&tmp, &path)?;
        #[cfg(not(windows))]
        tokio::fs::rename(&tmp, &path).await?;
        if let Some(parent) = path.parent() {
            sync_parent_directory(parent)?;
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

    /// Return a contiguous strict-replication history suffix, or `None` when
    /// the requested version predates retained history. Strict catchup must
    /// fail closed here and request a snapshot instead of treating a compacted
    /// tail as a complete log.
    pub async fn strict_log_entries_since_in_server(
        &self,
        server_id: &str,
        since_version: u64,
    ) -> Option<Vec<ChannelLogEntry>> {
        let _write_transaction = self.strict_apply_lock.lock().await;
        let current_version = self.current_version_in_server(server_id);
        if since_version >= current_version {
            return Some(Vec::new());
        }

        let entries: Vec<_> = self
            .log
            .read()
            .iter()
            .filter(|entry| entry.op.server_id == server_id && entry.op.version > since_version)
            .cloned()
            .collect();
        let mut expected_version = since_version.checked_add(1)?;
        for entry in &entries {
            if entry.op.version != expected_version {
                return None;
            }
            expected_version = expected_version.checked_add(1)?;
        }
        if expected_version.checked_sub(1) != Some(current_version) {
            return None;
        }

        Some(entries)
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
        let _write_transaction = self.strict_apply_lock.lock().await;
        if op.version <= self.current_version_in_server(&op.server_id) {
            return Ok(());
        }
        let (new_version, affected_acl_channels) = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(op.server_id.clone()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(&op.server_id, channels);
            let normalized_op = normalize_op_for_root(&op.op, &root_config);
            let mut should_invalidate_acl = channel_op_invalidates_acl_cache(&normalized_op);
            if let ChannelOp::SetAcls {
                channel_id,
                inherit_acl,
                acls,
            } = &normalized_op
            {
                should_invalidate_acl = channels.get(channel_id).is_some_and(|channel| {
                    channel.inherit_acl != *inherit_acl || channel.acls != *acls
                });
            }
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
            rebuild_effective_acl_caches_for_op(channels, &normalized_op);
            self.rebuild_ordered_channel_view_in_server(&op.server_id, channels);
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
        self.effective_acl_cache_dirty
            .store(true, Ordering::Release);

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
        let _write_transaction = self.strict_apply_lock.lock().await;
        self.apply_committed_operation_inner(op, None, None, false)
            .await
    }

    /// Compatibility entry point for committed operations that carry strict
    /// metadata. Metadata-bearing operations use the durable op-id ledger;
    /// callers that must suppress duplicate side effects should use
    /// [`Self::apply_strict_operation_once`] directly.
    pub async fn apply_committed_operation_with_metadata(
        self: &Arc<Self>,
        op: ChannelOperation,
        strict_metadata: Option<StrictReplicationMetadata>,
    ) -> Result<Arc<ChannelOperation>, ChannelRepoError> {
        match strict_metadata {
            Some(metadata) => self
                .apply_strict_operation_once_inner(op, metadata)
                .await
                .map(|(_, op)| op),
            None => {
                let _write_transaction = self.strict_apply_lock.lock().await;
                self.apply_committed_operation_inner(op, None, None, false)
                    .await
            }
        }
    }

    /// Atomically apply a strict operation at most once for this channel
    /// scope. The operation id is retained in the snapshot ledger and is
    /// rebuilt from WAL records during startup.
    pub async fn apply_strict_operation_once(
        self: &Arc<Self>,
        mut op: ChannelOperation,
        strict_metadata: StrictReplicationMetadata,
    ) -> Result<StrictOperationApplyOutcome, ChannelRepoError> {
        if op.server_id.is_empty() {
            op.server_id = default_server_id();
        }
        self.apply_strict_operation_once_inner(op, strict_metadata)
            .await
            .map(|(outcome, _)| outcome)
    }

    async fn apply_strict_operation_once_inner(
        self: &Arc<Self>,
        mut op: ChannelOperation,
        strict_metadata: StrictReplicationMetadata,
    ) -> Result<(StrictOperationApplyOutcome, Arc<ChannelOperation>), ChannelRepoError> {
        if op.server_id.is_empty() {
            op.server_id = default_server_id();
        }
        let strict_operation_id = StrictOperationKey::new(&op.server_id, strict_metadata);
        let _strict_apply_guard = self.strict_apply_lock.lock().await;

        if self
            .strict_applied_ops
            .read()
            .contains(&strict_operation_id)
        {
            return Ok((StrictOperationApplyOutcome::AlreadyApplied, Arc::new(op)));
        }
        if op.version <= self.current_version_in_server(&op.server_id) {
            return Ok((StrictOperationApplyOutcome::VersionConflict, Arc::new(op)));
        }

        let op = self.prepare_strict_operation_for_wal(op);
        self.append_wal_record(&op, Some(strict_metadata), false)
            .await?;
        let committed = self
            .apply_committed_operation_inner(
                op,
                Some(strict_metadata),
                Some(strict_operation_id),
                true,
            )
            .await?;
        Ok((StrictOperationApplyOutcome::Applied, committed))
    }

    /// Apply an S2S strict operation with durable WAL metadata. The strict
    /// replication terminal journal has already performed exact operation-id
    /// deduplication, so this path neither reads nor grows the legacy
    /// repository-owned operation-id ledger.
    pub async fn apply_s2s_strict_operation(
        self: &Arc<Self>,
        mut op: ChannelOperation,
        strict_metadata: StrictReplicationMetadata,
    ) -> Result<StrictOperationApplyOutcome, ChannelRepoError> {
        if op.server_id.is_empty() {
            op.server_id = default_server_id();
        }
        let _strict_apply_guard = self.strict_apply_lock.lock().await;
        if op.version <= self.current_version_in_server(&op.server_id) {
            return Ok(StrictOperationApplyOutcome::VersionConflict);
        }

        let op = self.prepare_strict_operation_for_wal(op);
        self.append_wal_record(&op, Some(strict_metadata), true)
            .await?;
        self.apply_committed_operation_inner(op, Some(strict_metadata), None, true)
            .await?;
        Ok(StrictOperationApplyOutcome::Applied)
    }

    async fn apply_committed_operation_inner(
        self: &Arc<Self>,
        mut op: ChannelOperation,
        strict_metadata: Option<StrictReplicationMetadata>,
        strict_operation_id: Option<StrictOperationKey>,
        wal_already_persisted: bool,
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
        let (evicting_pending_delete, affected_acl_channels, acl_change_hint) = {
            let mut all_channels = self.channels.write();
            let channels = all_channels.entry(server_id.clone()).or_default();
            let root_config = self.root_config.read().clone();
            ensure_root_channel(channels, &root_config);
            self.ensure_ordered_channel_view_in_server(&server_id, channels);
            op.op = normalize_op_for_root(&op.op, &root_config);
            let old_acl_state = match &op.op {
                ChannelOp::SetAcls { channel_id, .. } => channels
                    .get(channel_id)
                    .map(|channel| (channel.inherit_acl, channel.acls.clone())),
                _ => None,
            };
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
            rebuild_effective_acl_caches_for_op(channels, &op.op);
            self.rebuild_ordered_channel_view_in_server(&server_id, channels);
            apply_link_topology_effect(
                &self.link_topologies,
                &server_id,
                channels,
                link_topology_effect,
            );
            let acl_change_hint = match (&op.op, old_acl_state) {
                (
                    ChannelOp::SetAcls {
                        channel_id,
                        inherit_acl,
                        acls,
                    },
                    Some((old_inherit_acl, old_acls)),
                ) => Some(build_acl_change_hint(
                    channels,
                    *channel_id,
                    old_inherit_acl,
                    old_acls,
                    *inherit_acl,
                    acls,
                )),
                _ => None,
            };
            if let Some(hint) = &acl_change_hint {
                should_invalidate_acl = hint.impact.state_changed();
            }
            let affected_acl_channels = if let Some(hint) = &acl_change_hint {
                Some(hint.affected_channel_ids.iter().copied().collect())
            } else if deleted_subtree.is_some() {
                deleted_subtree
            } else {
                should_invalidate_acl
                    .then(|| acl_affected_channel_ids_for_op_in_map(channels, &op.op))
                    .flatten()
            };
            (
                evicting_pending_delete,
                affected_acl_channels,
                acl_change_hint,
            )
        };

        if let Some(affected_acl_channels) = affected_acl_channels {
            self.invalidate_acl_cache_for_op_scope(&server_id, affected_acl_channels);
        }
        let committed = self
            .commit_assigned_operation(
                op,
                strict_metadata,
                deleted_channel_hint,
                acl_change_hint,
                strict_operation_id,
                wal_already_persisted,
            )
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
        self.install_s2s_snapshot_with_strict_operation_ids(version, channels_snapshot, Vec::new())
            .await
    }

    /// Install a default-scope S2S snapshot together with strict operation
    /// ids already represented by the snapshot.
    pub async fn install_s2s_snapshot_with_strict_operation_ids(
        self: &Arc<Self>,
        version: u64,
        channels_snapshot: Vec<Channel>,
        strict_operation_ids: Vec<StrictOperationId>,
    ) -> Result<(), ChannelRepoError> {
        self.install_s2s_snapshot_with_strict_operation_ids_in_server(
            DEFAULT_SERVER_ID,
            version,
            channels_snapshot,
            chrono::Utc::now().timestamp(),
            strict_operation_ids,
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
        self.install_s2s_snapshot_with_strict_operation_ids_in_server(
            server_id,
            version,
            channels_snapshot,
            freshness,
            Vec::new(),
        )
        .await
    }

    /// Install an S2S snapshot and atomically merge the strict operation ids
    /// represented by it before the repository persists the snapshot.
    ///
    /// Any replacement snapshot must explicitly include every locally applied
    /// strict operation id for this server. Merging a missing local id into a
    /// snapshot that erased that operation's state would make a later replay
    /// look like an irreversible duplicate.
    pub async fn install_s2s_snapshot_with_strict_operation_ids_in_server(
        self: &Arc<Self>,
        server_id: &str,
        version: u64,
        channels_snapshot: Vec<Channel>,
        freshness: i64,
        strict_operation_ids: Vec<StrictOperationId>,
    ) -> Result<(), ChannelRepoError> {
        self.install_s2s_snapshot_candidate_in_server(
            server_id,
            version,
            channels_snapshot,
            freshness,
            strict_operation_ids,
            true,
        )
        .await
    }

    /// Install repository state paired with an S2S-owned delivery checkpoint.
    /// The existing legacy ledger is preserved on disk but is neither
    /// consulted nor expanded by this path.
    pub async fn install_s2s_checkpoint_snapshot_in_server(
        self: &Arc<Self>,
        server_id: &str,
        version: u64,
        channels_snapshot: Vec<Channel>,
        freshness: i64,
    ) -> Result<(), ChannelRepoError> {
        self.install_s2s_snapshot_candidate_in_server(
            server_id,
            version,
            channels_snapshot,
            freshness,
            Vec::new(),
            false,
        )
        .await
    }

    async fn install_s2s_snapshot_candidate_in_server(
        self: &Arc<Self>,
        server_id: &str,
        version: u64,
        channels_snapshot: Vec<Channel>,
        freshness: i64,
        strict_operation_ids: Vec<StrictOperationId>,
        require_legacy_id_superset: bool,
    ) -> Result<(), ChannelRepoError> {
        let _strict_apply_guard = self.strict_apply_lock.lock().await;
        let current_version = self.current_version_in_server(server_id);
        if version < current_version {
            tracing::debug!(
                server_id,
                current_version,
                snapshot_version = version,
                "ignoring stale s2s channel snapshot"
            );
            return Ok(());
        }
        if require_legacy_id_superset {
            let incoming_operation_ids: HashSet<_> = strict_operation_ids.iter().cloned().collect();
            let missing_operation_ids = self
                .strict_applied_ops
                .read()
                .iter()
                .filter(|operation| {
                    operation.server_id == server_id
                        && !incoming_operation_ids.contains(&operation.operation_id)
                })
                .count();
            if missing_operation_ids != 0 {
                return Err(ChannelRepoError::StrictSnapshotOperationIdsIncomplete {
                    missing: missing_operation_ids,
                });
            }
        }
        self.persist_s2s_snapshot_candidate(
            server_id,
            version,
            &channels_snapshot,
            freshness,
            &strict_operation_ids,
        )
        .await?;
        self.install_s2s_snapshot_in_server_inner(
            server_id,
            version,
            channels_snapshot,
            freshness,
            strict_operation_ids,
        )
        .await
    }

    /// Persist the replacement state before publishing it in memory. A failed
    /// snapshot write therefore leaves both the visible state and the strict
    /// operation ledger untouched, allowing catchup to retry safely.
    async fn persist_s2s_snapshot_candidate(
        &self,
        server_id: &str,
        version: u64,
        channels_snapshot: &[Channel],
        freshness: i64,
        strict_operation_ids: &[StrictOperationId],
    ) -> Result<(), ChannelRepoError> {
        if self.storage_dir.is_none() {
            return Ok(());
        }

        let root_config = self.root_config.read().clone();
        let mut channels_by_server = self.channels.read().clone();
        let mut replacement = HashMap::new();
        for mut channel in channels_snapshot.iter().cloned() {
            if channel.id == 0 {
                channel.name = root_config.name().to_owned();
            }
            replacement.insert(channel.id, Arc::new(channel));
        }
        ensure_root_channel(&mut replacement, &root_config);
        channels_by_server.insert(server_id.to_owned(), replacement);

        let mut versions = self.versions.read().clone();
        versions.insert(server_id.to_owned(), version);
        let mut history_freshness = self.history_freshness.read().clone();
        history_freshness.insert(server_id.to_owned(), freshness);
        let mut applied_operations = self.strict_applied_ops.read().clone();
        applied_operations.extend(
            strict_operation_ids
                .iter()
                .cloned()
                .map(|operation_id| StrictOperationKey::with_operation_id(server_id, operation_id)),
        );

        let snapshot = self.snapshot_from_state(
            versions,
            history_freshness,
            applied_operations,
            channels_by_server,
        );
        self.write_strict_snapshot_candidate(&snapshot).await
    }

    /// Persist strict snapshot state before exposing it in memory. A failed
    /// write makes the durable operation-id ledger ambiguous until restart.
    async fn write_strict_snapshot_candidate(
        &self,
        snapshot: &Snapshot,
    ) -> Result<(), ChannelRepoError> {
        let result = self.write_snapshot_atomically(snapshot).await;
        if result.is_err() {
            self.wal_poisoned.store(true, Ordering::Release);
        }
        result
    }

    async fn install_s2s_snapshot_in_server_inner(
        self: &Arc<Self>,
        server_id: &str,
        version: u64,
        channels_snapshot: Vec<Channel>,
        freshness: i64,
        strict_operation_ids: Vec<StrictOperationId>,
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
                    channels.insert(channel.id, Arc::new(channel));
                }
                ensure_root_channel(channels, &root_config);
                rebuild_all_effective_acl_caches_in_map(channels);
                self.rebuild_ordered_channel_view_in_server(server_id, channels);
                let mut link_topologies = self.link_topologies.write();
                sync_link_topology_for_server(&mut link_topologies, server_id, channels);
                ids.extend(channels.keys().copied());
                notification_channels
                    .extend(channels.values().map(|channel| channel.as_ref().clone()));
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
                self.acl_change_hints
                    .write()
                    .retain(|(hint_server_id, _), _| hint_server_id != server_id);
            }
            (ids, notification_channels, removed_channel_ids)
        };
        self.merge_strict_operation_ids_in_server_unpersisted(server_id, strict_operation_ids);
        self.history_freshness
            .write()
            .insert(server_id.to_owned(), freshness);
        self.channel_acl_generation.fetch_add(1, Ordering::AcqRel);
        self.acl_cache.clear_sync();
        self.effective_acl_cache_dirty
            .store(true, Ordering::Release);

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

    /// The strict write transaction is held by the caller. This dry run
    /// finalizes fields that depend on current state before the WAL record is
    /// made durable, without making that state visible in memory.
    fn prepare_strict_operation_for_wal(&self, mut op: ChannelOperation) -> ChannelOperation {
        let root_config = self.root_config.read().clone();
        op.op = normalize_op_for_root(&op.op, &root_config);

        if let ChannelOp::DeleteChannel { id, nonce } = &op.op {
            let mut channels = self
                .channels
                .read()
                .get(&op.server_id)
                .cloned()
                .unwrap_or_default();
            ensure_root_channel(&mut channels, &root_config);
            op.emits_client_message =
                apply_delete_channel_to_map(&mut channels, *id, *nonce).is_some();
        }

        op
    }

    /// Append and sync one WAL record before publishing a strict operation.
    /// Once sync reports an error, durability is ambiguous, so fail closed
    /// until restart rather than risking duplicate records in this process.
    async fn append_wal_record(
        &self,
        op: &ChannelOperation,
        strict_metadata: Option<StrictReplicationMetadata>,
        strict_id_owned_by_s2s: bool,
    ) -> Result<(), ChannelRepoError> {
        let Some(wal_mutex) = self.wal_file.as_ref() else {
            return Ok(());
        };
        if self.wal_poisoned.load(Ordering::Acquire) {
            return Err(ChannelRepoError::WalIo(io::Error::new(
                io::ErrorKind::Other,
                "channel WAL is unavailable after a previous sync failure",
            )));
        }

        let record = ChannelWalRecord::new(op, strict_metadata, strict_id_owned_by_s2s);
        let mut line =
            serde_json::to_string(&record).map_err(|e| ChannelRepoError::WalCorrupt {
                line: 0,
                reason: format!("WAL serialisation error: {e}"),
            })?;
        line.push('\n');

        let mut wal = wal_mutex.lock().await;
        let original_len = wal.metadata().await?.len();
        if let Err(error) = wal.write_all(line.as_bytes()).await {
            self.wal_poisoned.store(true, Ordering::Release);
            if let Err(truncate_error) = wal.set_len(original_len).await {
                tracing::warn!(error = ?truncate_error, "failed to truncate partial channel WAL record");
            }
            return Err(ChannelRepoError::WalIo(error));
        }

        #[cfg(test)]
        if self
            .force_next_wal_sync_failure
            .swap(false, Ordering::AcqRel)
        {
            self.wal_poisoned.store(true, Ordering::Release);
            return Err(ChannelRepoError::WalIo(io::Error::new(
                io::ErrorKind::Other,
                "forced channel WAL sync failure",
            )));
        }

        if let Err(error) = wal.sync_data().await {
            self.wal_poisoned.store(true, Ordering::Release);
            return Err(ChannelRepoError::WalIo(error));
        }

        self.wal_entry_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    #[cfg(test)]
    fn force_next_wal_sync_failure_for_test(&self) {
        self.force_next_wal_sync_failure
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn force_next_snapshot_write_failure_for_test(&self) {
        self.force_next_snapshot_write_failure
            .store(true, Ordering::Release);
    }

    async fn commit_assigned_operation(
        &self,
        mut op: ChannelOperation,
        strict_metadata: Option<StrictReplicationMetadata>,
        deleted_channel_ids: Option<Vec<u32>>,
        acl_change_hint: Option<AclChangeHint>,
        strict_operation_id: Option<StrictOperationKey>,
        wal_already_persisted: bool,
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
            if let Some(acl_change_hint) = acl_change_hint {
                self.acl_change_hints.write().insert(
                    (op.server_id.clone(), op.version),
                    Arc::new(acl_change_hint),
                );
            }
            while log.len() > self.log_max_entries {
                if let Some(evicted) = log.pop_front() {
                    self.delete_visibility_hints
                        .write()
                        .remove(&(evicted.op.server_id.clone(), evicted.op.version));
                    self.acl_change_hints
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

        if !wal_already_persisted {
            self.append_wal_record(&op, strict_metadata, false).await?;
        }

        // The WAL has been synced (or this repository is explicitly
        // in-memory), so the id can now be retained before any automatic
        // snapshot compaction runs.
        if let Some(strict_operation_id) = strict_operation_id {
            self.strict_applied_ops.write().insert(strict_operation_id);
        }

        // Program content changes only for ACL/tree operations, but the
        // aggregate cache checkpoint is locked to this repository version.
        // Coalesce that version advance into the next periodic snapshot.
        self.effective_acl_cache_dirty
            .store(true, Ordering::Release);

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
            // Every caller holds the write transaction, so taking it again
            // through `save_snapshot` would deadlock.
            let result = self.save_snapshot_inner().await;
            if let Err(e) = result {
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
        let _ = self
            .commit_assigned_operation(op, None, None, None, None, false)
            .await?;
        Ok(())
    }

    async fn commit_with_acl_change_hint(
        &self,
        mut op: ChannelOperation,
        acl_change_hint: AclChangeHint,
    ) -> Result<Arc<ChannelOperation>, ChannelRepoError> {
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
        let committed = self
            .commit_assigned_operation(op, None, None, Some(acl_change_hint), None, false)
            .await?;
        Ok(committed)
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
            .commit_assigned_operation(op, None, deleted_channel_ids, None, None, false)
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

#[cfg(windows)]
fn replace_file_atomically(temporary_path: &Path, path: &Path) -> io::Result<()> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;

    let temporary_wide = temporary_path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();

    // `ReplaceFileW` preserves the existing snapshot until the replacement is
    // committed. For the first write it reports NotFound, so use a same-volume
    // write-through move instead.
    let replaced = unsafe {
        ReplaceFileW(
            path_wide.as_ptr(),
            temporary_wide.as_ptr(),
            std::ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if replaced != 0 {
        return Ok(());
    }

    let replace_error = io::Error::last_os_error();
    if replace_error.kind() != io::ErrorKind::NotFound {
        return Err(replace_error);
    }

    let moved = unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            path_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    // Windows replacement uses write-through flags. Other platforms do not
    // expose a portable directory sync primitive through the standard library.
    Ok(())
}

fn next_available_channel_id(channels: &ChannelMap, temporary: bool) -> u32 {
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
    channels: &ChannelMap,
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
    channels: &mut ChannelMap,
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

fn effective_acl_cache_snapshot(
    versions: &HashMap<String, u64>,
    channels_by_server: &ChannelsByServer,
) -> EffectiveAclCacheSnapshot {
    let channels = channels_by_server
        .iter()
        .flat_map(|(server_id, channels)| {
            channels.values().filter_map(|channel| {
                channel
                    .effective_acl_cache
                    .as_deref()
                    .map(|program| EffectiveAclCacheChannel {
                        server_id: server_id.clone(),
                        channel_id: channel.id,
                        program: program.clone(),
                    })
            })
        })
        .collect();
    EffectiveAclCacheSnapshot {
        format_version: EFFECTIVE_ACL_CACHE_FORMAT_VERSION,
        versions: versions.clone(),
        state_fingerprints: channels_by_server
            .iter()
            .map(|(server_id, channels)| {
                (server_id.clone(), effective_acl_state_fingerprint(channels))
            })
            .collect(),
        channels,
    }
}

fn effective_acl_state_fingerprint(channels: &ChannelMap) -> u64 {
    let mut channels: Vec<_> = channels.values().collect();
    channels.sort_unstable_by_key(|channel| channel.id);

    let mut fingerprint = FxHasher::default();
    channels.len().hash(&mut fingerprint);
    for channel in channels {
        EffectiveAclSource(channel).hash(&mut fingerprint);
    }
    fingerprint.finish()
}

/// Hash view limited to fields that can change a channel's compiled effective
/// ACL. A blanket `Hash for Channel` would either hash unrelated state or give
/// `Channel` surprising partial-value hash semantics.
struct EffectiveAclSource<'a>(&'a Channel);

impl Hash for EffectiveAclSource<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.id.hash(state);
        self.0.parent_id.hash(state);
        self.0.inherit_acl.hash(state);
        self.0.acls.hash(state);
    }
}

async fn load_effective_acl_cache_checkpoint(
    storage_dir: &Path,
    authoritative_versions: &HashMap<String, u64>,
    channels_by_server: &mut ChannelsByServer,
) -> HashSet<String> {
    let path = storage_dir.join("channels.effective-acl-cache.json");
    let data = match tokio::fs::read(&path).await {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return HashSet::new(),
        Err(error) => {
            tracing::warn!(?path, %error, "failed to read effective ACL cache; rebuilding");
            return HashSet::new();
        }
    };
    let snapshot: EffectiveAclCacheSnapshot = match serde_json::from_slice(&data) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(?path, %error, "invalid effective ACL cache; rebuilding");
            return HashSet::new();
        }
    };
    if snapshot.format_version != EFFECTIVE_ACL_CACHE_FORMAT_VERSION {
        tracing::info!(
            ?path,
            cache_format = snapshot.format_version,
            expected_format = EFFECTIVE_ACL_CACHE_FORMAT_VERSION,
            "effective ACL cache format changed; rebuilding"
        );
        return HashSet::new();
    }

    let mut programs: HashMap<String, HashMap<u32, crate::acl::CompiledEffectiveAcl>> =
        HashMap::new();
    let mut duplicate = HashSet::new();
    for scoped in snapshot.channels {
        if programs
            .entry(scoped.server_id.clone())
            .or_default()
            .insert(scoped.channel_id, scoped.program)
            .is_some()
        {
            duplicate.insert(scoped.server_id);
        }
    }

    let mut loaded = HashSet::new();
    for (server_id, channels) in channels_by_server.iter_mut() {
        if duplicate.contains(server_id)
            || snapshot.versions.get(server_id) != authoritative_versions.get(server_id)
            || snapshot.state_fingerprints.get(server_id)
                != Some(&effective_acl_state_fingerprint(channels))
        {
            continue;
        }
        let Some(server_programs) = programs.remove(server_id) else {
            continue;
        };
        if server_programs.len() != channels.len()
            || channels.iter().any(|(channel_id, channel)| {
                !server_programs
                    .get(channel_id)
                    .is_some_and(|program| program.is_current(channel))
            })
        {
            continue;
        }
        for (channel_id, program) in server_programs {
            let Some(channel) = channels.get_mut(&channel_id) else {
                continue;
            };
            Arc::make_mut(channel).effective_acl_cache = Some(Arc::new(program));
        }
        loaded.insert(server_id.clone());
    }
    loaded
}

fn rebuild_all_effective_acl_caches(channels_by_server: &mut ChannelsByServer) {
    for channels in channels_by_server.values_mut() {
        rebuild_all_effective_acl_caches_in_map(channels);
    }
}

fn rebuild_all_effective_acl_caches_in_map(channels: &mut ChannelMap) {
    let channel_ids: HashSet<u32> = channels.keys().copied().collect();
    rebuild_effective_acl_caches(channels, channel_ids);
}

fn effective_acl_caches_are_complete(channels: &ChannelMap) -> bool {
    channels
        .values()
        .all(|channel| channel.has_effective_acl_cache())
}

fn rebuild_effective_acl_caches_for_subtree(channels: &mut ChannelMap, root_id: u32) {
    let channel_ids = collect_subtree(channels, root_id).into_iter().collect();
    rebuild_effective_acl_caches(channels, channel_ids);
}

fn rebuild_effective_acl_caches_for_op(channels: &mut ChannelMap, op: &ChannelOp) {
    match op {
        ChannelOp::CreateChannel { channel } => {
            rebuild_effective_acl_caches_for_subtree(channels, channel.id);
        }
        ChannelOp::SetAcls { channel_id, .. } => {
            rebuild_effective_acl_caches_for_subtree(channels, *channel_id);
        }
        ChannelOp::UpdateChannel { id, patch } | ChannelOp::EditChannel { id, patch, .. }
            if patch.parent_id.is_some() =>
        {
            rebuild_effective_acl_caches_for_subtree(channels, *id);
        }
        ChannelOp::InstallSnapshot { .. } => rebuild_all_effective_acl_caches_in_map(channels),
        ChannelOp::UpdateChannel { .. }
        | ChannelOp::EditChannel { .. }
        | ChannelOp::MarkPendingDelete { .. }
        | ChannelOp::DeleteChannel { .. }
        | ChannelOp::CancelPendingDelete { .. }
        | ChannelOp::AddLink { .. }
        | ChannelOp::RemoveLink { .. } => {}
    }
}

fn rebuild_effective_acl_caches(channels: &mut ChannelMap, channel_ids: HashSet<u32>) {
    for channel_id in channel_ids {
        let ancestors = ancestor_channels_in_map(channels, channel_id);
        let Some(current) = channels.get(&channel_id) else {
            continue;
        };
        let mut channel = current.as_ref().clone();
        channel.rebuild_effective_acl_cache(&ancestors);
        channels.insert(channel_id, Arc::new(channel));
    }
}

fn ancestor_channels_in_map(channels: &ChannelMap, channel_id: u32) -> Vec<Arc<Channel>> {
    let mut ancestors = Vec::new();
    let mut visited = HashSet::from([channel_id]);
    let mut current_id = channel_id;
    loop {
        let Some(parent_id) = channels
            .get(&current_id)
            .and_then(|channel| channel.parent_id)
        else {
            break;
        };
        if !visited.insert(parent_id) {
            break;
        }
        let Some(parent) = channels.get(&parent_id) else {
            break;
        };
        ancestors.push(Arc::clone(parent));
        current_id = parent_id;
    }
    ancestors
}

/// Apply a `ChannelOp` to the in-memory channel map.
fn apply_op_to_map(
    channels: &mut ChannelMap,
    op: &ChannelOp,
    origin_node: u16,
    root_config: &ChannelRootConfig,
) {
    let op = normalize_op_for_root(op, root_config);
    match &op {
        ChannelOp::CreateChannel { channel } => {
            channels.insert(channel.id, Arc::new(channel.clone()));
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
                    Arc::make_mut(ch).links.insert(*link_add);
                }
                if let Some(target) = channels.get_mut(link_add) {
                    Arc::make_mut(target).links.insert(*id);
                }
            }
            for link_remove in links_remove {
                if let Some(ch) = channels.get_mut(id) {
                    Arc::make_mut(ch).links.remove(link_remove);
                }
                if let Some(target) = channels.get_mut(link_remove) {
                    Arc::make_mut(target).links.remove(id);
                }
            }
            if let Some(ch) = channels.get_mut(id) {
                apply_patch(Arc::make_mut(ch), patch);
            }
        }
        ChannelOp::UpdateChannel { id, patch } => {
            if let Some(ch) = channels.get_mut(id) {
                apply_patch(Arc::make_mut(ch), patch);
            }
        }
        ChannelOp::MarkPendingDelete { id, nonce, .. } => {
            let started_at_ms = chrono::Utc::now().timestamp_millis();
            let to_mark = collect_subtree(channels, *id);
            for mark_id in to_mark {
                if let Some(ch) = channels.get_mut(&mark_id) {
                    Arc::make_mut(ch).pending_delete = Some(PendingDeleteState {
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
                        Arc::make_mut(ch).pending_delete = None;
                    }
                }
            }
        }
        ChannelOp::AddLink { a, b } => {
            if let Some(ch) = channels.get_mut(a) {
                Arc::make_mut(ch).links.insert(*b);
            }
            if let Some(ch) = channels.get_mut(b) {
                Arc::make_mut(ch).links.insert(*a);
            }
        }
        ChannelOp::RemoveLink { a, b } => {
            if let Some(ch) = channels.get_mut(a) {
                Arc::make_mut(ch).links.remove(b);
            }
            if let Some(ch) = channels.get_mut(b) {
                Arc::make_mut(ch).links.remove(a);
            }
        }
        ChannelOp::SetAcls {
            channel_id,
            inherit_acl,
            acls,
        } => {
            if let Some(ch) = channels.get_mut(channel_id) {
                let ch = Arc::make_mut(ch);
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
                channels.insert(channel.id, Arc::new(channel));
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
    channels: &mut ChannelMap,
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
    channels_by_server: &mut ChannelsByServer,
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
    channels: &mut ChannelMap,
) {
    normalize_channel_links(channels);
    link_topologies.insert(server_id.to_owned(), LinkTopology::from_channels(channels));
}

fn normalize_channel_links(channels: &mut ChannelMap) {
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
        Arc::make_mut(channel).links.clear();
    }

    for (a, b) in edges {
        if let Some(channel) = channels.get_mut(&a) {
            Arc::make_mut(channel).links.insert(b);
        }
        if let Some(channel) = channels.get_mut(&b) {
            Arc::make_mut(channel).links.insert(a);
        }
    }
}

fn deleted_channels_have_links(channels: &ChannelMap, deleted_ids: &[u32]) -> bool {
    deleted_ids.iter().any(|id| {
        channels
            .get(id)
            .is_some_and(|channel| !channel.links.is_empty())
    })
}

fn linked_neighbors_outside_deleted_subtree(
    channels: &ChannelMap,
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
    channels: &mut ChannelMap,
    neighbor_ids: &[u32],
    removed_ids: &[u32],
) {
    if neighbor_ids.is_empty() || removed_ids.is_empty() {
        return;
    }
    let removed_ids: HashSet<u32> = removed_ids.iter().copied().collect();
    for neighbor_id in neighbor_ids {
        if let Some(channel) = channels.get_mut(neighbor_id) {
            Arc::make_mut(channel)
                .links
                .retain(|linked_id| !removed_ids.contains(linked_id));
        }
    }
}

fn ordered_link_edge(a: u32, b: u32) -> (u32, u32) {
    if a < b { (a, b) } else { (b, a) }
}

fn ensure_root_channel(channels: &mut ChannelMap, root_config: &ChannelRootConfig) {
    channels
        .entry(0)
        .or_insert_with(|| Arc::new(root_channel(root_config)));
    if let Some(root) = channels.get_mut(&0) {
        if root.name != root_config.name() || root.parent_id.is_some() {
            let root = Arc::make_mut(root);
            root.name = root_config.name().to_owned();
            root.parent_id = None;
        }
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
            effective_acl_cache: None,
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
    channels: &ChannelMap,
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

fn channels_with_home_channel_dependent_acls_in_map(channels: &ChannelMap) -> HashSet<u32> {
    let mut children_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
    for channel in channels.values() {
        if let Some(parent_id) = channel.parent_id {
            children_by_parent
                .entry(parent_id)
                .or_default()
                .push(channel.id);
        }
    }
    let children_by_parent = children_by_parent
        .into_iter()
        .map(|(parent_id, children)| (parent_id, Arc::from(children.into_boxed_slice())))
        .collect();

    channels_with_home_channel_dependent_acls_with_children(channels, &children_by_parent)
}

fn channels_with_home_channel_dependent_acls_with_children(
    channels: &ChannelMap,
    children_by_parent: &HashMap<u32, Arc<[u32]>>,
) -> HashSet<u32> {
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
    channels: &ChannelMap,
    children_by_parent: &HashMap<u32, Arc<[u32]>>,
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
                    .is_some_and(group_depends_on_home_channel)
        });
    let applies_to_subs = channel.acls.iter().any(|acl| {
        acl.apply_subs
            && acl
                .group
                .as_deref()
                .is_some_and(group_depends_on_home_channel)
    });

    if applies_here {
        affected.insert(channel_id);
    }

    let descendant_inherited = inherited_home_channel_dependent_acl || applies_to_subs;
    if let Some(children) = children_by_parent.get(&channel_id) {
        for &child_id in children.iter() {
            collect_home_channel_dependent_acl_channel_ids(
                channels,
                children_by_parent,
                child_id,
                descendant_inherited,
                affected,
            );
        }
    }
}

/// Collect `root_id` and all of its descendants (BFS), returning their IDs.
fn collect_subtree(channels: &ChannelMap, root_id: u32) -> Vec<u32> {
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
fn is_descendant(channels: &ChannelMap, candidate: u32, ancestor_id: u32) -> bool {
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
    use crate::{
        ChannelHierarchy, ClientMembershipQuery,
        acl::{effective_acl_compile_count, reset_effective_acl_compile_count},
        evaluate_permission,
    };

    fn cached_permissions(depends_on_home_channel: bool) -> CachedAclPermissions {
        CachedAclPermissions {
            channel_acl_generation: 3,
            client_acl_subject_generation: 5,
            client_acl_home_generation: 7,
            depends_on_home_channel,
            explicit_enter_deny_overrides_write: false,
            permissions: ACLPermissions::Enter.into(),
        }
    }

    #[test]
    fn home_independent_acl_cache_entry_survives_home_generation_change() {
        let entry = cached_permissions(false);

        let hit = entry.hit_for(3, 5, 99, false).unwrap();
        let expected_permissions: BitFlags<ACLPermissions> = ACLPermissions::Enter.into();

        assert_eq!(hit.permissions(), expected_permissions);
        assert!(!hit.depends_on_home_channel());
        assert!(entry.hit_for(3, 6, 7, false).is_none());
    }

    #[test]
    fn home_dependent_acl_cache_entry_validates_home_generation() {
        let entry = cached_permissions(true);

        assert!(entry.hit_for(3, 5, 99, false).is_none());
        assert!(entry.hit_for(3, 5, 7, false).is_some());
    }

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

    fn test_acl(group: &str) -> ACL {
        ACL {
            user_id: None,
            group: Some(group.to_owned()),
            apply_here: true,
            apply_subs: false,
            allow: ACLPermissions::Enter.into(),
            deny: BitFlags::empty(),
        }
    }

    fn group_acl(
        group: &str,
        apply_here: bool,
        apply_subs: bool,
        allow: BitFlags<ACLPermissions>,
        deny: BitFlags<ACLPermissions>,
    ) -> ACL {
        ACL {
            user_id: None,
            group: Some(group.to_owned()),
            apply_here,
            apply_subs,
            allow,
            deny,
        }
    }

    fn cached_group_permissions(channel: &Channel, groups: &[&str]) -> BitFlags<ACLPermissions> {
        assert!(channel.has_effective_acl_cache());
        let membership = ClientMembershipQuery::new(groups, true, &[], None, false, None)
            .with_home_channel(ChannelHierarchy::new(channel.id, &[]));
        evaluate_permission(channel, &[], Some(7), &membership)
    }

    fn parent_patch(parent_id: u32) -> ChannelPatch {
        ChannelPatch {
            name: None,
            position: None,
            max_users: None,
            description_hash: None,
            parent_id: Some(Some(parent_id)),
        }
    }

    #[tokio::test]
    async fn persisted_open_eagerly_rebuilds_effective_acl_cache_after_wal_replay() {
        let dir = tempfile::tempdir().unwrap();
        {
            let repo = ChannelRepository::open(1, dir.path(), root_config(), tuning())
                .await
                .unwrap();
            repo.create_channel(Channel::new(1, "parent", 0, 0, Some(0)))
                .await
                .unwrap();
            repo.create_channel(Channel::new(2, "leaf", 0, 0, Some(1)))
                .await
                .unwrap();
            repo.set_acls(
                1,
                true,
                vec![group_acl(
                    "staff",
                    false,
                    true,
                    ACLPermissions::Move.into(),
                    BitFlags::empty(),
                )],
            )
            .await
            .unwrap();
        }

        let reopened = ChannelRepository::open(1, dir.path(), root_config(), tuning())
            .await
            .unwrap();
        let leaf = reopened.get_channel(2).await.unwrap();

        assert!(cached_group_permissions(&leaf, &["staff"]).contains(ACLPermissions::Move));
    }

    #[tokio::test]
    async fn persisted_effective_acl_cache_loads_without_recompiling() {
        let dir = tempfile::tempdir().unwrap();
        {
            let repo = ChannelRepository::open(1, dir.path(), root_config(), tuning())
                .await
                .unwrap();
            repo.create_channel(Channel::new(1, "parent", 0, 0, Some(0)))
                .await
                .unwrap();
            repo.create_channel(Channel::new(2, "leaf", 0, 0, Some(1)))
                .await
                .unwrap();
            repo.save_snapshot().await.unwrap();
        }

        reset_effective_acl_compile_count();
        let reopened = ChannelRepository::open(1, dir.path(), root_config(), tuning())
            .await
            .unwrap();

        assert_eq!(effective_acl_compile_count(), 0);
        assert!(
            reopened
                .get_channel(2)
                .await
                .unwrap()
                .has_effective_acl_cache()
        );
    }

    #[tokio::test]
    async fn persisted_effective_acl_cache_replays_only_changed_subtree() {
        let dir = tempfile::tempdir().unwrap();
        {
            let repo = ChannelRepository::open(1, dir.path(), root_config(), tuning())
                .await
                .unwrap();
            for channel in [
                Channel::new(1, "parent", 0, 0, Some(0)),
                Channel::new(2, "leaf", 0, 0, Some(1)),
                Channel::new(3, "sibling", 0, 0, Some(0)),
            ] {
                repo.create_channel(channel).await.unwrap();
            }
            repo.save_snapshot().await.unwrap();
            repo.set_acls(1, true, vec![test_acl("staff")])
                .await
                .unwrap();
        }

        reset_effective_acl_compile_count();
        let reopened = ChannelRepository::open(1, dir.path(), root_config(), tuning())
            .await
            .unwrap();

        assert_eq!(effective_acl_compile_count(), 2);
        assert!(
            reopened
                .get_channel(3)
                .await
                .unwrap()
                .has_effective_acl_cache()
        );
    }

    #[tokio::test]
    async fn unrelated_wal_versions_reuse_persisted_effective_acl_programs() {
        let dir = tempfile::tempdir().unwrap();
        {
            let repo = ChannelRepository::open(1, dir.path(), root_config(), tuning())
                .await
                .unwrap();
            repo.create_channel(Channel::new(1, "before", 0, 0, Some(0)))
                .await
                .unwrap();
            repo.save_snapshot().await.unwrap();
            repo.update_channel(
                1,
                ChannelPatch {
                    name: Some("after".to_owned()),
                    position: None,
                    max_users: None,
                    description_hash: None,
                    parent_id: None,
                },
            )
            .await
            .unwrap();
        }

        reset_effective_acl_compile_count();
        let reopened = ChannelRepository::open(1, dir.path(), root_config(), tuning())
            .await
            .unwrap();

        assert_eq!(effective_acl_compile_count(), 0);
        assert_eq!(reopened.get_channel(1).await.unwrap().name, "after");
    }

    #[tokio::test]
    async fn effective_acl_cache_gap_falls_back_to_one_full_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        {
            let repo = ChannelRepository::open(1, dir.path(), root_config(), tuning())
                .await
                .unwrap();
            for channel in [
                Channel::new(1, "parent", 0, 0, Some(0)),
                Channel::new(2, "leaf", 0, 0, Some(1)),
                Channel::new(3, "sibling", 0, 0, Some(0)),
            ] {
                repo.create_channel(channel).await.unwrap();
            }
            repo.save_snapshot().await.unwrap();
            let skipped_version = repo.current_version() + 2;
            repo.apply_committed_operation(ChannelOperation {
                server_id: DEFAULT_SERVER_ID.to_owned(),
                version: skipped_version,
                node_id: 2,
                timestamp: chrono::Utc::now().timestamp(),
                emits_client_message: true,
                op: ChannelOp::SetAcls {
                    channel_id: 1,
                    inherit_acl: true,
                    acls: vec![test_acl("staff")],
                },
            })
            .await
            .unwrap();
        }

        reset_effective_acl_compile_count();
        let reopened = ChannelRepository::open(1, dir.path(), root_config(), tuning())
            .await
            .unwrap();

        assert_eq!(effective_acl_compile_count(), 4);
        assert!(
            reopened
                .get_channel(2)
                .await
                .unwrap()
                .has_effective_acl_cache()
        );
    }

    #[tokio::test]
    async fn mismatched_effective_acl_input_fingerprint_rebuilds_cache() {
        let dir = tempfile::tempdir().unwrap();
        {
            let repo = ChannelRepository::open(1, dir.path(), root_config(), tuning())
                .await
                .unwrap();
            repo.create_channel(Channel::new(1, "channel", 0, 0, Some(0)))
                .await
                .unwrap();
            repo.save_snapshot().await.unwrap();
        }
        let path = dir.path().join("channels.effective-acl-cache.json");
        let mut checkpoint: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        checkpoint["state_fingerprints"][DEFAULT_SERVER_ID] = serde_json::json!(0);
        tokio::fs::write(&path, serde_json::to_vec(&checkpoint).unwrap())
            .await
            .unwrap();

        reset_effective_acl_compile_count();
        let reopened = ChannelRepository::open(1, dir.path(), root_config(), tuning())
            .await
            .unwrap();

        assert_eq!(effective_acl_compile_count(), 2);
        assert!(
            reopened
                .get_channel(1)
                .await
                .unwrap()
                .has_effective_acl_cache()
        );
    }

    #[tokio::test]
    async fn clean_effective_acl_cache_checkpoint_is_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let repo = ChannelRepository::open(1, dir.path(), root_config(), tuning())
            .await
            .unwrap();
        repo.create_channel(Channel::new(1, "channel", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.save_snapshot().await.unwrap();
        let path = dir.path().join("channels.effective-acl-cache.json");
        let before = tokio::fs::read(&path).await.unwrap();

        repo.save_snapshot().await.unwrap();

        assert_eq!(tokio::fs::read(path).await.unwrap(), before);
    }

    #[tokio::test]
    async fn own_acl_change_rebuilds_effective_acl_cache() {
        let repo = repo();
        repo.create_channel(Channel::new(1, "target", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.set_acls(
            1,
            true,
            vec![group_acl(
                "staff",
                true,
                false,
                ACLPermissions::Move.into(),
                BitFlags::empty(),
            )],
        )
        .await
        .unwrap();
        let target = repo.get_channel(1).await.unwrap();
        assert!(cached_group_permissions(&target, &["staff"]).contains(ACLPermissions::Move));

        repo.set_acls(
            1,
            true,
            vec![group_acl(
                "staff",
                true,
                false,
                BitFlags::empty(),
                ACLPermissions::Move.into(),
            )],
        )
        .await
        .unwrap();
        let target = repo.get_channel(1).await.unwrap();
        assert!(!cached_group_permissions(&target, &["staff"]).contains(ACLPermissions::Move));
    }

    #[tokio::test]
    async fn moving_subtree_rebuilds_effective_acl_caches() {
        let repo = repo();
        for channel in [
            Channel::new(1, "allow-parent", 0, 0, Some(0)),
            Channel::new(2, "deny-parent", 0, 0, Some(0)),
            Channel::new(3, "moved", 0, 0, Some(1)),
            Channel::new(4, "leaf", 0, 0, Some(3)),
        ] {
            repo.create_channel(channel).await.unwrap();
        }
        repo.set_acls(
            1,
            true,
            vec![group_acl(
                "staff",
                false,
                true,
                ACLPermissions::Move.into(),
                BitFlags::empty(),
            )],
        )
        .await
        .unwrap();
        repo.set_acls(
            2,
            true,
            vec![group_acl(
                "staff",
                false,
                true,
                BitFlags::empty(),
                ACLPermissions::Move.into(),
            )],
        )
        .await
        .unwrap();

        for id in [3, 4] {
            let channel = repo.get_channel(id).await.unwrap();
            assert!(cached_group_permissions(&channel, &["staff"]).contains(ACLPermissions::Move));
        }

        repo.update_channel(3, parent_patch(2)).await.unwrap();

        for id in [3, 4] {
            let channel = repo.get_channel(id).await.unwrap();
            assert!(!cached_group_permissions(&channel, &["staff"]).contains(ACLPermissions::Move));
        }
    }

    #[tokio::test]
    async fn ancestor_traverse_change_rebuilds_cache_below_inheritance_barrier() {
        let repo = repo();
        for channel in [
            Channel::new(1, "parent", 0, 0, Some(0)),
            Channel::new(2, "barrier", 0, 0, Some(1)),
            Channel::new(3, "leaf", 0, 0, Some(2)),
        ] {
            repo.create_channel(channel).await.unwrap();
        }
        repo.set_acls(2, false, Vec::new()).await.unwrap();
        let leaf = repo.get_channel(3).await.unwrap();
        assert!(!cached_group_permissions(&leaf, &["staff"]).is_empty());

        repo.set_acls(
            1,
            true,
            vec![group_acl(
                "staff",
                true,
                false,
                BitFlags::empty(),
                ACLPermissions::Traverse.into(),
            )],
        )
        .await
        .unwrap();
        let leaf = repo.get_channel(3).await.unwrap();
        assert!(cached_group_permissions(&leaf, &["staff"]).is_empty());
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
        channels.insert(
            temp_id,
            Arc::new(Channel::new(temp_id, "temp", 0, 0, Some(0))),
        );
        channels.insert(
            10,
            Arc::new(Channel::new(10, "legacy-child", 0, 0, Some(temp_id))),
        );

        assert_eq!(collect_subtree(&channels, temp_id), vec![temp_id]);
    }

    #[tokio::test]
    async fn channel_tree_snapshot_indexes_subtrees_and_ancestors_once() {
        let repo = repo();
        repo.create_channel(Channel::new(1, "one", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(3, "three", 0, 0, Some(1)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(2, "two", 0, 0, Some(1)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(4, "four", 0, 0, Some(2)))
            .await
            .unwrap();

        let snapshot = repo.channel_tree_snapshot_in_server(DEFAULT_SERVER_ID);

        assert_eq!(snapshot.len(), 5);
        assert_eq!(snapshot.subtree_ids(1), vec![1, 2, 3, 4]);
        assert_eq!(snapshot.subtree_closure_ids([2, 3]), vec![2, 3, 4]);
        assert_eq!(snapshot.ancestor_ids(4), Some([2, 1, 0].as_slice()));
        assert_eq!(snapshot.ancestor_ids(0), Some([].as_slice()));
        assert_eq!(snapshot.ancestor_ids(99), None);

        repo.create_channel(Channel::new(5, "later", 0, 0, Some(1)))
            .await
            .unwrap();
        assert!(snapshot.channel(5).is_none(), "snapshot must remain stable");
        assert_eq!(snapshot.subtree_ids(1), vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn channel_tree_snapshot_reuses_index_for_acl_operation_scope() {
        let repo = repo();
        repo.create_channel(Channel::new(1, "one", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(2, "two", 0, 0, Some(1)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(3, "three", 0, 0, Some(0)))
            .await
            .unwrap();

        let snapshot = repo.channel_tree_snapshot_in_server(DEFAULT_SERVER_ID);
        let affected = snapshot
            .acl_affected_channel_ids_for_op(&ChannelOp::SetAcls {
                channel_id: 1,
                inherit_acl: true,
                acls: Vec::new(),
            })
            .expect("ACL operation has a scoped affected set");

        assert_eq!(affected, HashSet::from([1, 2]));
        assert_eq!(snapshot.channels().count(), 4);
        assert_eq!(
            snapshot.channel_ids().collect::<HashSet<_>>(),
            HashSet::from([0, 1, 2, 3])
        );
    }

    #[test]
    fn channel_tree_snapshot_inheriting_subtree_stops_at_acl_barriers() {
        let mut channels = HashMap::from([
            (0, Arc::new(Channel::new(0, "root", 0, 0, None))),
            (1, Arc::new(Channel::new(1, "one", 0, 0, Some(0)))),
            (2, Arc::new(Channel::new(2, "two", 0, 0, Some(1)))),
            (3, Arc::new(Channel::new(3, "three", 0, 0, Some(1)))),
            (4, Arc::new(Channel::new(4, "four", 0, 0, Some(2)))),
            (5, Arc::new(Channel::new(5, "five", 0, 0, Some(3)))),
        ]);
        Arc::make_mut(channels.get_mut(&3).unwrap()).inherit_acl = false;
        let snapshot = ChannelTreeSnapshot::new(channels);

        assert_eq!(snapshot.inheriting_subtree_ids(1, true), vec![1, 2, 4]);
        assert_eq!(snapshot.inheriting_subtree_ids(1, false), vec![2, 4]);
    }

    #[tokio::test]
    async fn reparent_acl_scope_includes_home_channel_dependent_channels() {
        let repo = repo();
        for id in 1..=3 {
            repo.create_channel(Channel::new(id, format!("ch{id}"), 0, 0, Some(0)))
                .await
                .unwrap();
        }
        repo.set_acls(
            3,
            true,
            vec![ACL {
                user_id: None,
                group: Some("in".to_owned()),
                apply_here: true,
                apply_subs: false,
                allow: enumflags2::BitFlags::empty(),
                deny: enumflags2::BitFlags::empty(),
            }],
        )
        .await
        .unwrap();

        repo.update_channel(
            1,
            ChannelPatch {
                name: None,
                position: None,
                max_users: None,
                description_hash: None,
                parent_id: Some(Some(2)),
            },
        )
        .await
        .unwrap();

        let op = repo
            .get_log_since(0)
            .await
            .into_iter()
            .find(|op| matches!(op.op, ChannelOp::UpdateChannel { id: 1, .. }))
            .expect("reparent operation");
        let affected = repo
            .acl_affected_channel_ids_for_op(DEFAULT_SERVER_ID, &op.op)
            .await
            .expect("server channel map");

        assert_eq!(affected, HashSet::from([1, 3]));
    }

    #[tokio::test]
    async fn identical_acl_update_does_not_advance_or_invalidate_repository_state() {
        let repo = repo();
        repo.create_channel(Channel::new(1, "channel", 0, 0, Some(0)))
            .await
            .unwrap();
        let acls = vec![test_acl("all")];

        assert!(
            repo.set_acls_if_changed(1, false, acls.clone())
                .await
                .unwrap()
        );

        let version = repo.current_version();
        let log_len = repo.get_log_since(0).await.len();
        let acl_generation = repo.channel_acl_generation_for_channel(DEFAULT_SERVER_ID, 1);
        let expected_permissions: BitFlags<ACLPermissions> = ACLPermissions::Enter.into();
        repo.cache_permissions(10, 20, 1, acl_generation, 30, expected_permissions)
            .await;

        let observer = Arc::new(RecordingObserver::default());
        repo.set_observer(observer.clone());
        let mut operations = repo.subscribe();

        assert!(
            !repo
                .set_acls_if_changed(1, false, acls.clone())
                .await
                .unwrap()
        );
        // The compatibility wrapper must share the same no-op behavior.
        repo.set_acls(1, false, acls.clone()).await.unwrap();

        assert_eq!(repo.current_version(), version);
        assert_eq!(repo.get_log_since(0).await.len(), log_len);
        assert_eq!(
            repo.channel_acl_generation_for_channel(DEFAULT_SERVER_ID, 1),
            acl_generation
        );
        assert_eq!(
            repo.get_cached_permissions(10, 20, 1, acl_generation, 30)
                .await,
            Some(expected_permissions)
        );
        assert_eq!(repo.get_channel(1).await.unwrap().acls, acls);
        assert!(matches!(
            operations.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(
            observer
                .versions
                .lock()
                .expect("recording observer mutex poisoned")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn acl_change_result_distinguishes_inheritance_and_entries() {
        let repo = repo();
        repo.create_channel(Channel::new(1, "channel", 0, 0, Some(0)))
            .await
            .unwrap();

        assert!(
            repo.set_acls_if_changed(1, false, vec![test_acl("all")])
                .await
                .unwrap()
        );
        assert!(
            repo.set_acls_if_changed(1, true, vec![test_acl("all")])
                .await
                .unwrap()
        );
        assert!(
            repo.set_acls_if_changed(1, true, vec![test_acl("auth")])
                .await
                .unwrap()
        );

        let channel = repo.get_channel(1).await.unwrap();
        assert!(channel.inherit_acl);
        assert_eq!(channel.acls, vec![test_acl("auth")]);
    }

    #[tokio::test]
    async fn local_acl_operation_retains_before_and_shared_after_context() {
        let repo = repo();
        repo.create_channel(Channel::new(1, "channel", 0, 0, Some(0)))
            .await
            .unwrap();
        let old_acls = vec![test_acl("all")];
        repo.set_acls(1, false, old_acls.clone()).await.unwrap();

        let first_new_version = repo.current_version() + 1;
        let new_acls = vec![test_acl("auth")];
        repo.set_acls(1, true, new_acls.clone()).await.unwrap();
        let op = repo
            .get_log_since(first_new_version - 1)
            .await
            .into_iter()
            .find(|op| op.version == first_new_version)
            .expect("ACL operation is retained in the log");
        let hint = repo
            .acl_change_hint_for_operation(&op)
            .expect("ACL operation has transient change context");

        assert_eq!(hint.channel_id(), 1);
        assert!(!hint.old_inherit_acl());
        assert_eq!(hint.old_acls(), old_acls);
        assert!(hint.impact().state_changed());
        assert!(hint.impact().inheritance_changed());
        let snapshot = hint.tree_snapshot();
        let changed = snapshot.channel(1).unwrap();
        assert!(changed.inherit_acl);
        assert_eq!(changed.acls, new_acls);
    }

    #[tokio::test]
    async fn replicated_acl_noop_advances_version_without_invalidating_cache() {
        let repo = repo();
        repo.create_channel(Channel::new(1, "channel", 0, 0, Some(0)))
            .await
            .unwrap();
        let acls = vec![test_acl("all")];
        repo.set_acls(1, false, acls.clone()).await.unwrap();
        let old_version = repo.current_version();
        let old_generation = repo.channel_acl_generation_for_channel(DEFAULT_SERVER_ID, 1);

        let committed = repo
            .apply_committed_operation(ChannelOperation {
                server_id: DEFAULT_SERVER_ID.to_owned(),
                version: old_version + 1,
                node_id: 2,
                timestamp: 123,
                emits_client_message: true,
                op: ChannelOp::SetAcls {
                    channel_id: 1,
                    inherit_acl: false,
                    acls: acls.clone(),
                },
            })
            .await
            .unwrap();

        assert_eq!(repo.current_version(), old_version + 1);
        assert_eq!(
            repo.channel_acl_generation_for_channel(DEFAULT_SERVER_ID, 1),
            old_generation
        );
        let hint = repo
            .acl_change_hint_for_operation(&committed)
            .expect("replicated no-op publishes an ACL hint");
        assert!(!hint.impact().state_changed());
        assert!(hint.affected_channel_ids().is_empty());
        assert_eq!(hint.old_acls(), acls);
    }

    #[tokio::test]
    async fn acl_hint_scopes_here_and_sub_permissions_across_inheritance_barriers() {
        let repo = repo();
        for (id, parent_id) in [(1, 0), (2, 1), (3, 1), (4, 2)] {
            let mut channel = Channel::new(id, format!("ch{id}"), 0, 0, Some(parent_id));
            if id == 3 {
                channel.inherit_acl = false;
            }
            repo.create_channel(channel).await.unwrap();
        }

        let mut speak_here = test_acl("all");
        speak_here.allow = ACLPermissions::Speak.into();
        let version = repo.current_version() + 1;
        repo.set_acls(1, true, vec![speak_here]).await.unwrap();
        let speak_op = repo
            .get_log_since(version - 1)
            .await
            .into_iter()
            .find(|op| op.version == version)
            .unwrap();
        assert_eq!(
            repo.acl_change_hint_for_operation(&speak_op)
                .unwrap()
                .affected_channel_ids(),
            &[1]
        );

        let mut traverse_here = test_acl("all");
        traverse_here.allow = ACLPermissions::Traverse.into();
        let version = repo.current_version() + 1;
        repo.set_acls(1, true, vec![traverse_here]).await.unwrap();
        let traverse_here_op = repo
            .get_log_since(version - 1)
            .await
            .into_iter()
            .find(|op| op.version == version)
            .unwrap();
        let traverse_here_hint = repo
            .acl_change_hint_for_operation(&traverse_here_op)
            .unwrap();
        assert_eq!(traverse_here_hint.affected_channel_ids(), &[1, 2, 3, 4]);
        assert_eq!(
            traverse_here_hint.tree_snapshot().subtree_ids(1),
            vec![1, 2, 3, 4],
            "structural Traverse visibility closure is intentionally separate"
        );

        repo.set_acls(1, true, Vec::new()).await.unwrap();
        let mut traverse_subs = test_acl("all");
        traverse_subs.apply_here = false;
        traverse_subs.apply_subs = true;
        traverse_subs.allow = ACLPermissions::Traverse.into();
        let version = repo.current_version() + 1;
        repo.set_acls(1, true, vec![traverse_subs]).await.unwrap();
        let traverse_op = repo
            .get_log_since(version - 1)
            .await
            .into_iter()
            .find(|op| op.version == version)
            .unwrap();
        assert_eq!(
            repo.acl_change_hint_for_operation(&traverse_op)
                .unwrap()
                .affected_channel_ids(),
            &[2, 4]
        );
    }

    #[tokio::test]
    async fn acl_hints_expire_with_log_eviction_and_snapshot_replacement() {
        let repo = repo_with_log_max_entries(1);
        repo.create_channel(Channel::new(1, "channel", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.set_acls(1, true, vec![test_acl("all")]).await.unwrap();
        let acl_op = repo.get_log_since(0).await.pop().unwrap();
        assert!(repo.acl_change_hint_for_operation(&acl_op).is_some());

        repo.create_channel(Channel::new(2, "other", 0, 0, Some(0)))
            .await
            .unwrap();
        assert!(repo.acl_change_hint_for_operation(&acl_op).is_none());

        repo.set_acls(1, true, vec![test_acl("auth")])
            .await
            .unwrap();
        let acl_op = repo.get_log_since(0).await.pop().unwrap();
        assert!(repo.acl_change_hint_for_operation(&acl_op).is_some());
        let channels = repo
            .get_all()
            .await
            .into_iter()
            .map(|channel| channel.as_ref().clone())
            .collect();
        repo.install_s2s_snapshot(repo.current_version(), channels)
            .await
            .unwrap();
        assert!(repo.acl_change_hint_for_operation(&acl_op).is_none());
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
    async fn simultaneous_temporary_channels_get_distinct_ids() {
        let repo = repo();

        let alice_temp = repo.next_channel_id(true).await;
        repo.create_channel(Channel::new(alice_temp, "AliceTemp", 0, 0, Some(0)))
            .await
            .unwrap();

        let bob_temp = repo.next_channel_id(true).await;
        repo.create_channel(Channel::new(bob_temp, "BobTemp", 0, 0, Some(0)))
            .await
            .unwrap();

        assert_ne!(
            alice_temp, bob_temp,
            "active temporary channels must not reuse the same id"
        );
        assert_eq!(
            repo.get_channel(alice_temp).await.unwrap().name,
            "AliceTemp"
        );
        assert_eq!(repo.get_channel(bob_temp).await.unwrap().name, "BobTemp");
    }

    #[tokio::test]
    async fn removed_temporary_channel_id_is_reused() {
        let repo = repo();

        let first_temp = repo.next_channel_id(true).await;
        repo.create_channel(Channel::new(first_temp, "ReusableTemp", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.delete_channel(first_temp).await.unwrap();
        assert!(
            repo.get_channel(first_temp).await.is_none(),
            "precondition: temporary channel should be removed before reuse"
        );

        let second_temp = repo.next_channel_id(true).await;
        repo.create_channel(Channel::new(second_temp, "ReusedTemp", 0, 0, Some(0)))
            .await
            .unwrap();

        assert_eq!(
            second_temp, first_temp,
            "temporary channel ids should be recycled once the old channel has been removed"
        );
        assert_eq!(
            repo.get_channel(second_temp).await.unwrap().name,
            "ReusedTemp"
        );
    }

    #[tokio::test]
    async fn subscribed_snapshot_receives_followup_channel_operations() {
        let repo = repo();
        let (channels, version, mut rx) = repo
            .ordered_snapshot_with_version_and_subscription_in_server("alpha")
            .await;

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
    async fn repository_snapshots_reuse_root_first_position_order_after_mutations() {
        let repo = repo();
        repo.create_channel(Channel::new(3, "right", 0, 1, Some(0)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(2, "left", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(5, "left-child", 0, 0, Some(2)))
            .await
            .unwrap();
        repo.create_channel(Channel::new(4, "right-child", 0, 0, Some(3)))
            .await
            .unwrap();

        let ids = repo
            .get_all()
            .await
            .into_iter()
            .map(|channel| channel.id)
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![0, 2, 3, 5, 4]);

        let (before_update, _, _) =
            repo.snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
        let (same_view, _, _) =
            repo.snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
        assert!(Arc::ptr_eq(&before_update, &same_view));
        let authoritative_before =
            Arc::clone(repo.channels.read()[DEFAULT_SERVER_ID].get(&3).unwrap());
        let ordered_before = before_update
            .iter()
            .find(|channel| channel.id == 3)
            .unwrap();
        let tree_before = repo.channel_tree_snapshot_in_server(DEFAULT_SERVER_ID);
        let tree_channel_before = tree_before.channels.get(&3).unwrap();
        assert!(Arc::ptr_eq(&authoritative_before, ordered_before));
        assert!(Arc::ptr_eq(&authoritative_before, tree_channel_before));
        let unchanged_before = Arc::clone(repo.channels.read()[DEFAULT_SERVER_ID].get(&2).unwrap());
        let root_before = Arc::clone(repo.channels.read()[DEFAULT_SERVER_ID].get(&0).unwrap());

        repo.create_channel(Channel::new(99, "right", 0, 0, Some(0)))
            .await
            .expect_err("duplicate sibling name is rejected");
        let after_rejection = repo.ordered_snapshot_in_server(DEFAULT_SERVER_ID);
        assert!(Arc::ptr_eq(
            &root_before,
            repo.channels.read()[DEFAULT_SERVER_ID].get(&0).unwrap()
        ));
        assert!(Arc::ptr_eq(&root_before, &after_rejection[0]));

        repo.update_channel(
            3,
            ChannelPatch {
                name: Some("renamed-right".to_owned()),
                position: None,
                max_users: Some(42),
                description_hash: None,
                parent_id: None,
            },
        )
        .await
        .unwrap();
        let (content_update, _, _) =
            repo.snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
        assert!(!Arc::ptr_eq(&before_update, &content_update));
        assert_eq!(
            before_update
                .iter()
                .find(|channel| channel.id == 3)
                .unwrap()
                .name
                .as_str(),
            "right"
        );
        let updated = content_update
            .iter()
            .find(|channel| channel.id == 3)
            .unwrap();
        assert_eq!(updated.name.as_str(), "renamed-right");
        assert_eq!(updated.max_users, 42);
        assert!(!Arc::ptr_eq(&authoritative_before, updated));
        assert!(Arc::ptr_eq(
            &unchanged_before,
            content_update
                .iter()
                .find(|channel| channel.id == 2)
                .unwrap()
        ));

        repo.set_acls(3, false, vec![test_acl("staff")])
            .await
            .unwrap();
        let (acl_update, _, _) =
            repo.snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
        assert!(!Arc::ptr_eq(&content_update, &acl_update));
        assert!(
            content_update
                .iter()
                .find(|channel| channel.id == 3)
                .unwrap()
                .acls
                .is_empty()
        );
        assert_eq!(
            acl_update
                .iter()
                .find(|channel| channel.id == 3)
                .unwrap()
                .acls
                .len(),
            1
        );

        repo.update_channel(
            3,
            ChannelPatch {
                name: None,
                position: Some(-1),
                max_users: None,
                description_hash: None,
                parent_id: None,
            },
        )
        .await
        .unwrap();
        let (channels, _, _) =
            repo.snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
        assert!(!Arc::ptr_eq(&acl_update, &channels));
        assert_eq!(
            channels
                .iter()
                .map(|channel| channel.id)
                .collect::<Vec<_>>(),
            vec![0, 3, 2, 4, 5]
        );
        assert_eq!(
            repo.channel_tree_snapshot_in_server(DEFAULT_SERVER_ID)
                .ordered_channels()
                .map(|channel| channel.id)
                .collect::<Vec<_>>(),
            vec![0, 3, 2, 4, 5]
        );
    }

    #[tokio::test]
    async fn installed_snapshot_order_preserves_orphans_cycles_and_server_scope() {
        let repo = repo();
        repo.create_channel_in_server("beta", Channel::new(10, "beta", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.install_s2s_snapshot_in_server(
            "alpha",
            7,
            vec![
                Channel::new(7, "orphan", 0, 0, Some(99)),
                Channel::new(3, "right", 0, 1, Some(0)),
                Channel::new(0, "ignored-root-name", 0, 0, None),
                Channel::new(2, "left", 0, 0, Some(0)),
                Channel::new(5, "left-child", 0, 0, Some(2)),
                Channel::new(9, "cycle-b", 0, 0, Some(8)),
                Channel::new(8, "cycle-a", 0, 0, Some(9)),
            ],
            11,
        )
        .await
        .unwrap();

        assert_eq!(
            repo.get_all_in_server("alpha")
                .await
                .into_iter()
                .map(|channel| channel.id)
                .collect::<Vec<_>>(),
            vec![0, 2, 3, 5, 9, 8, 7]
        );
        assert_eq!(
            repo.get_all_in_server("beta")
                .await
                .into_iter()
                .map(|channel| channel.id)
                .collect::<Vec<_>>(),
            vec![0, 10]
        );
    }

    #[test]
    fn ordered_snapshot_synthesizes_root_before_building_breadth_first_order() {
        let repo = repo();
        {
            let mut all_channels = repo.channels.write();
            let channels = all_channels.get_mut(DEFAULT_SERVER_ID).unwrap();
            channels.clear();
            channels.insert(3, Arc::new(Channel::new(3, "first", 0, 0, Some(0))));
            channels.insert(2, Arc::new(Channel::new(2, "second", 1, 0, Some(0))));
            channels.insert(4, Arc::new(Channel::new(4, "first-child", 0, 0, Some(3))));
            channels.insert(5, Arc::new(Channel::new(5, "second-child", 0, 0, Some(2))));
            repo.ordered_channels.write().remove(DEFAULT_SERVER_ID);
        }

        assert_eq!(
            repo.ordered_snapshot_in_server(DEFAULT_SERVER_ID)
                .iter()
                .map(|channel| channel.id)
                .collect::<Vec<_>>(),
            vec![0, 3, 2, 4, 5]
        );
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

    #[tokio::test]
    async fn strict_channel_operation_is_applied_once_by_op_id() {
        let repo = repo();
        let metadata = StrictReplicationMetadata::new(11, 22, 33);
        let first = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 123,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "first", 0, 0, Some(0)),
            },
        };

        assert_eq!(
            repo.apply_strict_operation_once(first, metadata)
                .await
                .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let duplicate = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 2,
            node_id: 1,
            timestamp: 124,
            emits_client_message: true,
            op: ChannelOp::UpdateChannel {
                id: 9,
                patch: ChannelPatch {
                    name: Some("duplicate".to_owned()),
                    position: None,
                    max_users: None,
                    description_hash: None,
                    parent_id: None,
                },
            },
        };

        assert_eq!(
            repo.apply_strict_operation_once(
                duplicate,
                StrictReplicationMetadata::new(11, 22, 999),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::AlreadyApplied
        );
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.get_channel(9).await.unwrap().name, "first");
        assert_eq!(
            repo.get_log_entries_since(DEFAULT_SERVER_ID, 0).await.len(),
            1
        );
        assert_eq!(
            repo.strict_operation_ids(),
            vec![StrictOperationId::new(11, 22)]
        );
    }

    #[tokio::test]
    async fn concurrent_strict_channel_operations_claim_one_op_id() {
        let repo = repo();
        let metadata = StrictReplicationMetadata::new(21, 22, 23);
        let op = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 123,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "once", 0, 0, Some(0)),
            },
        };

        let (first, second) = tokio::join!(
            repo.apply_strict_operation_once(op.clone(), metadata),
            repo.apply_strict_operation_once(op, metadata),
        );
        let outcomes = [first.unwrap(), second.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == StrictOperationApplyOutcome::Applied)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == StrictOperationApplyOutcome::AlreadyApplied)
                .count(),
            1
        );
        assert_eq!(repo.current_version(), 1);
        assert_eq!(
            repo.get_log_entries_since(DEFAULT_SERVER_ID, 0).await.len(),
            1
        );
    }

    #[tokio::test]
    async fn strict_channel_op_id_survives_snapshot_compaction_and_restart() {
        let temp = tempfile::tempdir().unwrap();
        let mut compacting_tuning = tuning();
        compacting_tuning.log_max_entries = 1;
        compacting_tuning.wal_compaction_expire_count = 10;
        compacting_tuning.snapshot_every_ops = 100;
        let metadata = StrictReplicationMetadata::new(44, 55, 66);

        {
            let repo = ChannelRepository::open(1, temp.path(), root_config(), compacting_tuning)
                .await
                .unwrap();
            let first = ChannelOperation {
                server_id: DEFAULT_SERVER_ID.to_owned(),
                version: 1,
                node_id: 1,
                timestamp: 123,
                emits_client_message: true,
                op: ChannelOp::CreateChannel {
                    channel: Channel::new(9, "first", 0, 0, Some(0)),
                },
            };
            assert_eq!(
                repo.apply_strict_operation_once(first, metadata)
                    .await
                    .unwrap(),
                StrictOperationApplyOutcome::Applied
            );
            repo.apply_committed_operation(ChannelOperation {
                server_id: DEFAULT_SERVER_ID.to_owned(),
                version: 2,
                node_id: 1,
                timestamp: 124,
                emits_client_message: true,
                op: ChannelOp::UpdateChannel {
                    id: 9,
                    patch: ChannelPatch {
                        name: Some("snapshot-state".to_owned()),
                        position: None,
                        max_users: None,
                        description_hash: None,
                        parent_id: None,
                    },
                },
            })
            .await
            .unwrap();
            repo.save_snapshot().await.unwrap();
        }

        let repo = ChannelRepository::open(1, temp.path(), root_config(), compacting_tuning)
            .await
            .unwrap();
        assert_eq!(
            repo.strict_operation_ids(),
            vec![StrictOperationId::new(44, 55)]
        );

        let duplicate = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 3,
            node_id: 1,
            timestamp: 125,
            emits_client_message: true,
            op: ChannelOp::UpdateChannel {
                id: 9,
                patch: ChannelPatch {
                    name: Some("replayed".to_owned()),
                    position: None,
                    max_users: None,
                    description_hash: None,
                    parent_id: None,
                },
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(duplicate, metadata)
                .await
                .unwrap(),
            StrictOperationApplyOutcome::AlreadyApplied
        );
        assert_eq!(repo.current_version(), 2);
        assert_eq!(repo.get_channel(9).await.unwrap().name, "snapshot-state");
        assert!(
            repo.strict_log_entries_since_in_server(DEFAULT_SERVER_ID, 0)
                .await
                .is_none(),
            "a compacted tail must not masquerade as history from version zero"
        );
        assert_eq!(
            repo.strict_log_entries_since_in_server(DEFAULT_SERVER_ID, 1)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn channel_snapshot_merges_strict_operation_ids() {
        let repo = repo();
        let operation_id = StrictOperationId::new(71, 72);
        repo.install_s2s_snapshot_with_strict_operation_ids(
            1,
            vec![Channel::new(9, "snapshot", 0, 0, Some(0))],
            vec![operation_id.clone()],
        )
        .await
        .unwrap();

        let duplicate = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 2,
            node_id: 1,
            timestamp: 123,
            emits_client_message: true,
            op: ChannelOp::UpdateChannel {
                id: 9,
                patch: ChannelPatch {
                    name: Some("replayed".to_owned()),
                    position: None,
                    max_users: None,
                    description_hash: None,
                    parent_id: None,
                },
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(duplicate, StrictReplicationMetadata::new(71, 72, 1),)
                .await
                .unwrap(),
            StrictOperationApplyOutcome::AlreadyApplied
        );
        assert_eq!(repo.get_channel(9).await.unwrap().name, "snapshot");
    }

    #[tokio::test]
    async fn strict_snapshot_rejects_an_equal_version_replacement_missing_a_local_operation_id() {
        let repo = repo();
        let local_operation_id = StrictOperationId::new(81, 82);
        let local = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 123,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "local", 0, 0, Some(0)),
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(
                local,
                StrictReplicationMetadata::new(
                    local_operation_id.op_id_hi(),
                    local_operation_id.op_id_lo(),
                    1,
                ),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        assert!(matches!(
            repo.install_s2s_snapshot_with_strict_operation_ids(
                1,
                vec![Channel::new(10, "replacement", 0, 0, Some(0))],
                vec![StrictOperationId::new(83, 84)],
            )
            .await,
            Err(ChannelRepoError::StrictSnapshotOperationIdsIncomplete { missing: 1 })
        ));
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.get_channel(9).await.unwrap().name, "local");
        assert!(repo.get_channel(10).await.is_none());
        assert_eq!(repo.strict_operation_ids(), vec![local_operation_id]);
    }

    #[tokio::test]
    async fn strict_snapshot_rejects_a_newer_replacement_missing_a_local_operation_id() {
        let repo = repo();
        let local_operation_id = StrictOperationId::new(85, 86);
        let local = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 125,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "local", 0, 0, Some(0)),
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(
                local,
                StrictReplicationMetadata::new(
                    local_operation_id.op_id_hi(),
                    local_operation_id.op_id_lo(),
                    1,
                ),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );
        let before = repo.strict_snapshot_in_server(DEFAULT_SERVER_ID).await;

        assert!(matches!(
            repo.install_s2s_snapshot_with_strict_operation_ids(
                2,
                vec![Channel::new(10, "replacement", 0, 0, Some(0))],
                vec![StrictOperationId::new(87, 88)],
            )
            .await,
            Err(ChannelRepoError::StrictSnapshotOperationIdsIncomplete { missing: 1 })
        ));

        let after = repo.strict_snapshot_in_server(DEFAULT_SERVER_ID).await;
        assert_eq!(after.version(), before.version());
        assert_eq!(after.freshness(), before.freshness());
        assert_eq!(after.operation_ids(), before.operation_ids());
        assert_eq!(repo.get_channel(9).await.unwrap().name, "local");
        assert!(repo.get_channel(10).await.is_none());
    }

    #[tokio::test]
    async fn strict_snapshot_accepts_a_newer_replacement_with_a_superset_ledger() {
        let repo = repo();
        let local_operation_id = StrictOperationId::new(91, 92);
        let local = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 126,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "local", 0, 0, Some(0)),
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(
                local,
                StrictReplicationMetadata::new(
                    local_operation_id.op_id_hi(),
                    local_operation_id.op_id_lo(),
                    1,
                ),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let incoming_operation_id = StrictOperationId::new(93, 94);
        repo.install_s2s_snapshot_with_strict_operation_ids(
            2,
            vec![Channel::new(10, "replacement", 0, 0, Some(0))],
            vec![local_operation_id.clone(), incoming_operation_id.clone()],
        )
        .await
        .unwrap();

        assert_eq!(repo.current_version(), 2);
        assert!(repo.get_channel(9).await.is_none());
        assert_eq!(repo.get_channel(10).await.unwrap().name, "replacement");
        assert_eq!(
            repo.strict_operation_ids(),
            vec![local_operation_id, incoming_operation_id]
        );
    }

    #[tokio::test]
    async fn strict_snapshot_ledger_guard_is_scoped_to_its_server() {
        let repo = repo();
        let other_server_operation = ChannelOperation {
            server_id: "other-server".to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 127,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "other", 0, 0, Some(0)),
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(
                other_server_operation,
                StrictReplicationMetadata::new(95, 96, 1),
            )
            .await
            .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        repo.install_s2s_snapshot_with_strict_operation_ids(
            1,
            vec![Channel::new(10, "default", 0, 0, Some(0))],
            Vec::new(),
        )
        .await
        .unwrap();

        assert_eq!(repo.get_channel(10).await.unwrap().name, "default");
        assert_eq!(
            repo.get_channel_in_server("other-server", 9)
                .await
                .unwrap()
                .name,
            "other"
        );
    }

    #[tokio::test]
    async fn strict_operation_with_unknown_id_at_covered_version_is_a_conflict() {
        let repo = repo();
        let first = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 123,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "first", 0, 0, Some(0)),
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(first, StrictReplicationMetadata::new(1, 2, 3))
                .await
                .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let conflicting = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 2,
            timestamp: 124,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(10, "conflict", 0, 0, Some(0)),
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(conflicting, StrictReplicationMetadata::new(4, 5, 6),)
                .await
                .unwrap(),
            StrictOperationApplyOutcome::VersionConflict
        );

        assert_eq!(repo.current_version(), 1);
        assert!(repo.get_channel(10).await.is_none());
        assert_eq!(
            repo.get_log_entries_since(DEFAULT_SERVER_ID, 0).await.len(),
            1
        );
        assert_eq!(
            repo.strict_operation_ids(),
            vec![StrictOperationId::new(1, 2)]
        );
    }

    #[tokio::test]
    async fn strict_snapshot_bundle_includes_matching_state_and_operation_ids() {
        let repo = repo();
        let metadata = StrictReplicationMetadata::new(31, 32, 33);
        let op = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 456,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "strict", 0, 0, Some(0)),
            },
        };
        assert_eq!(
            repo.apply_strict_operation_once(op, metadata)
                .await
                .unwrap(),
            StrictOperationApplyOutcome::Applied
        );

        let snapshot = repo.strict_snapshot_in_server(DEFAULT_SERVER_ID).await;
        assert_eq!(snapshot.version(), 1);
        assert_eq!(snapshot.freshness(), 456);
        assert!(
            snapshot
                .channels()
                .iter()
                .any(|channel| channel.id == 9 && channel.name == "strict")
        );
        assert_eq!(snapshot.operation_ids(), &[StrictOperationId::new(31, 32)]);
    }

    #[tokio::test]
    async fn s2s_snapshot_preserves_the_frozen_legacy_compatibility_ledger() {
        let repo = repo();
        let op = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 456,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "strict", 0, 0, Some(0)),
            },
        };
        repo.apply_strict_operation_once(op, StrictReplicationMetadata::new(31, 32, 33))
            .await
            .unwrap();

        let snapshot = repo.s2s_snapshot_in_server(DEFAULT_SERVER_ID).await;
        assert_eq!(snapshot.version(), 1);
        assert_eq!(snapshot.operation_ids(), &[StrictOperationId::new(31, 32)]);
        assert_eq!(
            repo.strict_operation_ids(),
            vec![StrictOperationId::new(31, 32)]
        );
    }

    #[tokio::test]
    async fn s2s_strict_apply_does_not_grow_legacy_ledger_even_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        {
            let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
                .await
                .unwrap();
            let op = ChannelOperation {
                server_id: DEFAULT_SERVER_ID.to_owned(),
                version: 1,
                node_id: 1,
                timestamp: 456,
                emits_client_message: true,
                op: ChannelOp::CreateChannel {
                    channel: Channel::new(9, "strict", 0, 0, Some(0)),
                },
            };
            assert_eq!(
                repo.apply_s2s_strict_operation(op, StrictReplicationMetadata::new(31, 32, 33),)
                    .await
                    .unwrap(),
                StrictOperationApplyOutcome::Applied
            );
            assert!(repo.strict_operation_ids().is_empty());
        }

        let reopened = ChannelRepository::open(1, temp.path(), root_config(), tuning())
            .await
            .unwrap();
        assert_eq!(reopened.current_version(), 1);
        assert_eq!(reopened.get_channel(9).await.unwrap().name, "strict");
        assert!(reopened.strict_operation_ids().is_empty());
    }

    #[tokio::test]
    async fn s2s_checkpoint_snapshot_preserves_but_does_not_require_legacy_ledger() {
        let repo = repo();
        let legacy_operation_id = StrictOperationId::new(31, 32);
        repo.merge_strict_operation_ids(vec![legacy_operation_id.clone()])
            .await
            .unwrap();

        repo.install_s2s_checkpoint_snapshot_in_server(
            DEFAULT_SERVER_ID,
            1,
            vec![Channel::new(9, "replacement", 0, 0, Some(0))],
            456,
        )
        .await
        .unwrap();

        assert_eq!(repo.get_channel(9).await.unwrap().name, "replacement");
        assert_eq!(repo.strict_operation_ids(), vec![legacy_operation_id]);
    }

    #[tokio::test]
    async fn failed_strict_wal_sync_does_not_publish_memory_state() {
        let temp = tempfile::tempdir().unwrap();
        let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
            .await
            .unwrap();
        assert!(repo.strict_operation_durability_enabled());
        repo.force_next_wal_sync_failure_for_test();
        let op = ChannelOperation {
            server_id: DEFAULT_SERVER_ID.to_owned(),
            version: 1,
            node_id: 1,
            timestamp: 123,
            emits_client_message: true,
            op: ChannelOp::CreateChannel {
                channel: Channel::new(9, "unpublished", 0, 0, Some(0)),
            },
        };

        assert!(matches!(
            repo.apply_strict_operation_once(op, StrictReplicationMetadata::new(41, 42, 43))
                .await,
            Err(ChannelRepoError::WalIo(_))
        ));
        assert_eq!(repo.current_version(), 0);
        assert!(repo.get_channel(9).await.is_none());
        assert!(
            repo.get_log_entries_since(DEFAULT_SERVER_ID, 0)
                .await
                .is_empty()
        );
        assert!(repo.strict_operation_ids().is_empty());
        assert!(!repo.strict_operation_durability_enabled());
    }

    #[tokio::test]
    async fn failed_s2s_snapshot_write_does_not_publish_replacement_state() {
        let temp = tempfile::tempdir().unwrap();
        let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
            .await
            .unwrap();
        assert!(repo.strict_operation_durability_enabled());
        repo.create_channel(Channel::new(7, "existing", 0, 0, Some(0)))
            .await
            .unwrap();
        repo.force_next_snapshot_write_failure_for_test();

        assert!(matches!(
            repo.install_s2s_snapshot_with_strict_operation_ids(
                5,
                vec![Channel::new(9, "replacement", 0, 0, Some(0))],
                vec![StrictOperationId::new(51, 52)],
            )
            .await,
            Err(ChannelRepoError::WalIo(_))
        ));
        assert_eq!(repo.current_version(), 1);
        assert_eq!(repo.get_channel(7).await.unwrap().name, "existing");
        assert!(repo.get_channel(9).await.is_none());
        assert!(repo.strict_operation_ids().is_empty());
        assert!(!repo.strict_operation_durability_enabled());
    }

    #[tokio::test]
    async fn semantic_s2s_snapshot_rejection_does_not_poison_strict_durability() {
        let temp = tempfile::tempdir().unwrap();
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
                channel: Channel::new(7, "local", 0, 0, Some(0)),
            },
        };
        repo.apply_strict_operation_once(op, StrictReplicationMetadata::new(61, 62, 63))
            .await
            .unwrap();

        assert!(matches!(
            repo.install_s2s_snapshot_with_strict_operation_ids(
                1,
                vec![Channel::new(9, "replacement", 0, 0, Some(0))],
                Vec::new(),
            )
            .await,
            Err(ChannelRepoError::StrictSnapshotOperationIdsIncomplete { missing: 1 })
        ));
        assert!(repo.strict_operation_durability_enabled());
    }

    #[tokio::test]
    async fn failed_operation_id_ledger_snapshot_does_not_publish_ids() {
        let temp = tempfile::tempdir().unwrap();
        let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
            .await
            .unwrap();
        assert!(repo.strict_operation_durability_enabled());
        repo.force_next_snapshot_write_failure_for_test();

        assert!(matches!(
            repo.merge_strict_operation_ids(vec![StrictOperationId::new(61, 62)])
                .await,
            Err(ChannelRepoError::WalIo(_))
        ));
        assert!(repo.strict_operation_ids().is_empty());
        assert!(!repo.strict_operation_durability_enabled());
    }

    #[tokio::test]
    async fn persisted_s2s_snapshots_can_replace_an_existing_snapshot_file() {
        let temp = tempfile::tempdir().unwrap();
        {
            let repo = ChannelRepository::open(1, temp.path(), root_config(), tuning())
                .await
                .unwrap();
            repo.install_s2s_snapshot_with_strict_operation_ids(
                1,
                vec![Channel::new(7, "first", 0, 0, Some(0))],
                vec![StrictOperationId::new(71, 72)],
            )
            .await
            .unwrap();
            repo.install_s2s_snapshot_with_strict_operation_ids(
                2,
                vec![Channel::new(9, "second", 0, 0, Some(0))],
                vec![
                    StrictOperationId::new(71, 72),
                    StrictOperationId::new(73, 74),
                ],
            )
            .await
            .unwrap();
            repo.install_s2s_snapshot_with_strict_operation_ids(
                1,
                vec![Channel::new(10, "stale", 0, 0, Some(0))],
                vec![StrictOperationId::new(75, 76)],
            )
            .await
            .unwrap();
            assert_eq!(repo.current_version(), 2);
            assert!(repo.get_channel(10).await.is_none());
        }

        let reopened = ChannelRepository::open(1, temp.path(), root_config(), tuning())
            .await
            .unwrap();
        assert_eq!(reopened.current_version(), 2);
        assert!(reopened.get_channel(7).await.is_none());
        assert_eq!(reopened.get_channel(9).await.unwrap().name, "second");
        assert_eq!(
            reopened.strict_operation_ids(),
            vec![
                StrictOperationId::new(71, 72),
                StrictOperationId::new(73, 74)
            ]
        );
    }
}
