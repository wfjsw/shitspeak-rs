use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use tokio::net::TcpStream;
use tokio::sync::{RwLock as AsyncRwLock, broadcast, mpsc};
use tokio_rustls::server::TlsStream;

use shitspeak_s2s::application::voice::{RecipientIndexKey, RecipientIndexSnapshot};

use crate::{
    client::{
        Client, ClientInstanceId, ClientStateSubscription,
        client_session_identifier::ClientSessionIdentifier,
        next_client_instance_id,
        state_log::{
            ClientGlobalStateDelta, ClientStateBroadcastPayload, ClientStateLogEntry,
            ClientStateOperation,
        },
    },
    constants::MAX_LOCAL_SESSION_ID,
    types::{DEFAULT_SERVER_ID, ScopedChannelId, ScopedSessionId},
};

const MAX_CLIENT_ORIGIN_SNAPSHOT_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpBindingKey {
    remote_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
}

impl UdpBindingKey {
    fn legacy(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            local_addr: None,
        }
    }

    fn scoped(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            local_addr: Some(local_addr),
        }
    }
}

pub struct ClientRepository {
    local_node_id: u16,
    log_max_entries: usize,

    /// Locally-owned clients, local log state, and local voice-routing
    /// indexes. This lock is intentionally independent from replicated
    /// remote users so S2S lag cannot queue ahead of local movement.
    register: Arc<AsyncRwLock<ClientRegister>>,
    /// Replicated client state, sharded by owning node. A delayed stream from
    /// one remote node should not block local users or another remote node.
    remote_registers: Arc<AsyncRwLock<HashMap<u16, Arc<AsyncRwLock<RemoteClientRegister>>>>>,

    clients_by_host: ParkingRwLock<HashMap<IpAddr, HashSet<ScopedSessionId>>>,
    clients_by_udp_address: ParkingRwLock<HashMap<UdpBindingKey, ScopedSessionId>>,

    // These pools store only the local_session_id part, independently per server_id.
    allocation_pointers: ParkingMutex<HashMap<String, u32>>,
    free_ids: ParkingMutex<HashMap<String, HashSet<u32>>>,

    /// Broadcast channel for per-client subscribers and future S2S peers.
    tx: broadcast::Sender<Arc<ClientStateBroadcastPayload>>,
    deferred_commit_tx: Option<mpsc::UnboundedSender<DeferredClientCommit>>,
    deferred_commit_pending: Arc<AtomicUsize>,
    versions: Arc<ClientVersionIndex>,
    authenticated_client_counts: AuthenticatedClientCounts,
}

#[derive(Default)]
struct AuthenticatedClientCounts {
    by_server: ParkingRwLock<HashMap<String, Arc<AtomicU64>>>,
}

impl AuthenticatedClientCounts {
    fn counter(&self, server_id: &str) -> Arc<AtomicU64> {
        if let Some(counter) = self.by_server.read().get(server_id).cloned() {
            return counter;
        }
        Arc::clone(
            self.by_server
                .write()
                .entry(server_id.to_owned())
                .or_insert_with(|| Arc::new(AtomicU64::new(0))),
        )
    }

    fn get(&self, server_id: &str) -> u64 {
        self.by_server
            .read()
            .get(server_id)
            .map(|counter| counter.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    fn try_increment_below(&self, server_id: &str, limit: u64) -> bool {
        let counter = self.counter(server_id);
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < limit).then_some(count + 1)
            })
            .is_ok()
    }

    fn increment(&self, server_id: &str) {
        self.counter(server_id).fetch_add(1, Ordering::AcqRel);
    }

    fn decrement(&self, server_id: &str) {
        let counter = self.counter(server_id);
        let result = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            count.checked_sub(1)
        });
        debug_assert!(result.is_ok(), "authenticated client count underflow");
    }

    fn replace_remote_counts(
        &self,
        previous: &HashMap<String, u64>,
        replacement: &HashMap<String, u64>,
    ) {
        let server_ids = previous
            .keys()
            .chain(replacement.keys())
            .collect::<HashSet<_>>();
        for server_id in server_ids {
            let old = previous.get(server_id).copied().unwrap_or(0);
            let new = replacement.get(server_id).copied().unwrap_or(0);
            match new.cmp(&old) {
                std::cmp::Ordering::Greater => {
                    self.counter(server_id)
                        .fetch_add(new - old, Ordering::AcqRel);
                }
                std::cmp::Ordering::Less => {
                    let counter = self.counter(server_id);
                    let delta = old - new;
                    let result =
                        counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            count.checked_sub(delta)
                        });
                    debug_assert!(result.is_ok(), "authenticated client count underflow");
                }
                std::cmp::Ordering::Equal => {}
            }
        }
    }
}

fn authenticated_counts_by_server(
    clients: &HashMap<ScopedSessionId, Arc<Box<Client>>>,
) -> HashMap<String, u64> {
    let mut counts = HashMap::new();
    for client in clients.values() {
        *counts.entry(client.server_id()).or_default() += 1;
    }
    counts
}

pub(crate) struct ClientSnapshotWithVersions {
    clients: Vec<Arc<Box<Client>>>,
    versions: HashMap<u16, u64>,
    epochs: HashMap<u16, u64>,
}

impl ClientSnapshotWithVersions {
    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (Vec<Arc<Box<Client>>>, HashMap<u16, u64>) {
        (self.clients, self.versions)
    }

    pub(crate) fn into_projection_parts(
        self,
    ) -> (Vec<Arc<Box<Client>>>, HashMap<u16, u64>, HashMap<u16, u64>) {
        (self.clients, self.versions, self.epochs)
    }
}

pub struct ClientOriginRebase {
    origin: u16,
    version: u64,
    epoch: Option<u64>,
    entries: Vec<Arc<ClientStateLogEntry>>,
}

impl ClientOriginRebase {
    pub fn origin(&self) -> u16 {
        self.origin
    }

    #[cfg(test)]
    pub(crate) fn version(&self) -> u64 {
        self.version
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[Arc<ClientStateLogEntry>] {
        &self.entries
    }

    #[cfg(test)]
    pub(crate) fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    pub fn into_parts(self) -> (u16, u64, Option<u64>, Vec<Arc<ClientStateLogEntry>>) {
        (self.origin, self.version, self.epoch, self.entries)
    }
}

pub struct ClientProjectionCatchUp {
    rebases: Vec<ClientOriginRebase>,
    entries: Vec<Arc<ClientStateLogEntry>>,
    target_versions: HashMap<u16, u64>,
    target_epochs: HashMap<u16, u64>,
}

impl ClientProjectionCatchUp {
    #[cfg(test)]
    pub(crate) fn rebases(&self) -> &[ClientOriginRebase] {
        &self.rebases
    }

    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[Arc<ClientStateLogEntry>] {
        &self.entries
    }

    #[cfg(test)]
    pub(crate) fn target_versions(&self) -> &HashMap<u16, u64> {
        &self.target_versions
    }

    #[cfg(test)]
    pub(crate) fn target_epochs(&self) -> &HashMap<u16, u64> {
        &self.target_epochs
    }

    pub fn into_parts(
        self,
    ) -> (
        Vec<ClientOriginRebase>,
        Vec<Arc<ClientStateLogEntry>>,
        HashMap<u16, u64>,
        HashMap<u16, u64>,
    ) {
        (
            self.rebases,
            self.entries,
            self.target_versions,
            self.target_epochs,
        )
    }
}

struct DeferredClientCommit {
    op: ClientStateOperation,
    channel_version_dep: Option<u64>,
}

enum AuthenticatedClientCountChange {
    Added(String),
    Removed(String),
}

pub(crate) enum ClientOriginLogSlice {
    Available(Vec<Arc<ClientStateLogEntry>>),
    TooOld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientSnapshotInstallOutcome {
    Installed,
    Deferred,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(crate) struct ClientSnapshotInstallError {
    message: String,
}

impl ClientSnapshotInstallError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Default)]
struct ClientServerVersions {
    log: u64,
    voice_routing: u64,
}

#[derive(Default)]
struct ClientVersionIndex {
    global: AtomicU64,
    by_server: ParkingRwLock<HashMap<String, ClientServerVersions>>,
}

impl ClientVersionIndex {
    fn record(&self, op: &ClientStateOperation, version: u64) {
        self.global.store(version, Ordering::Release);
        let mut by_server = self.by_server.write();
        let entry = by_server.entry(op.server_id().to_owned()).or_default();
        entry.log = version;
        if op.affects_voice_routing() {
            entry.voice_routing = version;
        }
    }

    fn current(&self) -> u64 {
        self.global.load(Ordering::Acquire)
    }

    fn current_in_server(&self, server_id: &str) -> u64 {
        self.by_server
            .read()
            .get(server_id)
            .map(|versions| versions.log)
            .unwrap_or(0)
    }

    fn voice_routing_in_server(&self, server_id: &str) -> u64 {
        self.by_server
            .read()
            .get(server_id)
            .map(|versions| versions.voice_routing)
            .unwrap_or(0)
    }
}

pub struct ClientRegister {
    /// Clients homed on this node.
    local_clients: HashMap<ScopedSessionId, Arc<Box<Client>>>,
    /// Local sessions that own a slot in `authenticated_client_counts`.
    authenticated_local_clients: HashSet<ScopedSessionId>,
    /// Ring buffer of local log entries.
    local_log: VecDeque<Arc<ClientStateLogEntry>>,
    /// Monotonic local version counter.
    version: u64,

    // ── Channel membership index (LOCAL clients only) ───────────────────
    // Used by voice routing to find recipients on this node.  Remote
    // clients are deliberately excluded — they receive voice via S2S
    // cross-node delivery routed by their owning node.
    /// Maps (server_id, channel_id) → set of local session IDs currently in that channel.
    clients_by_channel: HashMap<ScopedChannelId, HashSet<ScopedSessionId>>,
    /// Reverse map: local session key → current channel key, for O(1) index moves.
    client_channel: HashMap<ScopedSessionId, ScopedChannelId>,
    /// Maps (server_id, channel_id) → set of local session IDs listening to that channel.
    listeners_by_channel: HashMap<ScopedChannelId, HashSet<ScopedSessionId>>,
}

struct RemoteClientRegister {
    /// Overlay boot epoch that owns the materialized state in this shard.
    /// `None` means that no epoch-fenced owner state has been observed yet.
    epoch: Option<u64>,
    /// Whether this shard represents a currently materialized origin. An
    /// offline removal retains the epoch fence but is not relay-advertised.
    materialized: bool,
    /// Versions at or below this point came from a materialized snapshot and
    /// must not be offered as an incremental owner-replication history.
    snapshot_history_floor: u64,
    /// Highest version admitted in this epoch. Unlike `version`, this survives
    /// transient offline removal and fences stale same-epoch resurrection.
    epoch_version_floor: u64,
    clients: HashMap<ScopedSessionId, Arc<Box<Client>>>,
    log: VecDeque<Arc<ClientStateLogEntry>>,
    version: u64,
    clients_by_channel: HashMap<ScopedChannelId, HashSet<ScopedSessionId>>,
    client_channel: HashMap<ScopedSessionId, ScopedChannelId>,
    listeners_by_channel: HashMap<ScopedChannelId, HashSet<ScopedSessionId>>,
    /// Remote client log entries waiting for channel state to catch up.
    /// Entries remain in this remote node's version order.
    pending_ops: VecDeque<(Arc<ClientStateLogEntry>, u64)>,
    /// Last pending effective dependency per server scope.
    last_pending_effective_dep_by_server: HashMap<String, u64>,
    /// Latest known channel version per server scope, used to release pending ops in order.
    pending_channel_versions: HashMap<String, u64>,
}

impl ClientRegister {
    /// Iterate over locally connected clients.
    fn local_clients(&self) -> impl Iterator<Item = &Arc<Box<Client>>> {
        self.local_clients.values()
    }

    /// Insert a client into the channel index.
    fn channel_index_insert(&mut self, id: ScopedSessionId, channel_id: u32) {
        let channel_key = ScopedChannelId::new(id.server_id().to_owned(), channel_id);
        self.client_channel.insert(id.clone(), channel_key.clone());
        self.clients_by_channel
            .entry(channel_key)
            .or_default()
            .insert(id);
    }

    /// Move a client from its current channel to `new_channel` in the index.
    fn channel_index_move(&mut self, id: ScopedSessionId, new_channel: u32) {
        let new_channel_key = ScopedChannelId::new(id.server_id().to_owned(), new_channel);
        let old = self.client_channel.get(&id).cloned();
        if old.as_ref() == Some(&new_channel_key) {
            return;
        }
        if let Some(old_ch) = old {
            if let Some(set) = self.clients_by_channel.get_mut(&old_ch) {
                set.remove(&id);
                if set.is_empty() {
                    self.clients_by_channel.remove(&old_ch);
                }
            }
        }
        self.client_channel
            .insert(id.clone(), new_channel_key.clone());
        self.clients_by_channel
            .entry(new_channel_key)
            .or_default()
            .insert(id);
    }

    /// Remove a client from the channel index entirely.
    fn channel_index_remove(&mut self, id: &ScopedSessionId) {
        if let Some(old_ch) = self.client_channel.remove(id) {
            if let Some(set) = self.clients_by_channel.get_mut(&old_ch) {
                set.remove(id);
                if set.is_empty() {
                    self.clients_by_channel.remove(&old_ch);
                }
            }
        }
    }

    /// Add `id` as a listener for `channel_id`.
    fn listener_index_add(&mut self, id: ScopedSessionId, channel_id: u32) {
        let channel_key = ScopedChannelId::new(id.server_id().to_owned(), channel_id);
        self.listeners_by_channel
            .entry(channel_key)
            .or_default()
            .insert(id);
    }

    /// Remove `id` from the listener set for a specific channel.
    fn listener_index_remove_channel(&mut self, id: &ScopedSessionId, channel_id: u32) {
        let channel_key = ScopedChannelId::new(id.server_id().to_owned(), channel_id);
        if let Some(set) = self.listeners_by_channel.get_mut(&channel_key) {
            set.remove(id);
            if set.is_empty() {
                self.listeners_by_channel.remove(&channel_key);
            }
        }
    }

    /// Remove `id` from all listener sets (called on disconnect).
    fn listener_index_remove_all(&mut self, id: &ScopedSessionId) {
        self.listeners_by_channel.retain(|_, set| {
            set.remove(id);
            !set.is_empty()
        });
    }

    fn sync_local_client_indexes(&mut self, scoped_id: &ScopedSessionId, client: &Client) {
        self.channel_index_move(scoped_id.clone(), client.get_current_channel_id());
        self.listener_index_remove_all(scoped_id);
        for channel_id in client.get_listening_channel_ids() {
            self.listener_index_add(scoped_id.clone(), channel_id);
        }
    }
}

impl RemoteClientRegister {
    fn new() -> Self {
        Self {
            epoch: None,
            materialized: false,
            snapshot_history_floor: 0,
            epoch_version_floor: 0,
            clients: HashMap::new(),
            log: VecDeque::new(),
            version: 0,
            clients_by_channel: HashMap::new(),
            client_channel: HashMap::new(),
            listeners_by_channel: HashMap::new(),
            pending_ops: VecDeque::new(),
            last_pending_effective_dep_by_server: HashMap::new(),
            pending_channel_versions: HashMap::new(),
        }
    }

    fn clear_materialized_state(&mut self) {
        self.clients.clear();
        self.log.clear();
        self.version = 0;
        self.snapshot_history_floor = 0;
        self.clients_by_channel.clear();
        self.client_channel.clear();
        self.listeners_by_channel.clear();
        self.pending_ops.clear();
        self.last_pending_effective_dep_by_server.clear();
        self.pending_channel_versions.clear();
    }

    fn channel_index_insert(&mut self, id: ScopedSessionId, channel_id: u32) {
        let channel_key = ScopedChannelId::new(id.server_id().to_owned(), channel_id);
        self.client_channel.insert(id.clone(), channel_key.clone());
        self.clients_by_channel
            .entry(channel_key)
            .or_default()
            .insert(id);
    }

    fn channel_index_move(&mut self, id: ScopedSessionId, new_channel: u32) {
        let new_channel_key = ScopedChannelId::new(id.server_id().to_owned(), new_channel);
        let old = self.client_channel.get(&id).cloned();
        if old.as_ref() == Some(&new_channel_key) {
            return;
        }
        if let Some(old_ch) = old {
            if let Some(set) = self.clients_by_channel.get_mut(&old_ch) {
                set.remove(&id);
                if set.is_empty() {
                    self.clients_by_channel.remove(&old_ch);
                }
            }
        }
        self.client_channel
            .insert(id.clone(), new_channel_key.clone());
        self.clients_by_channel
            .entry(new_channel_key)
            .or_default()
            .insert(id);
    }

    fn channel_index_remove(&mut self, id: &ScopedSessionId) {
        if let Some(old_ch) = self.client_channel.remove(id) {
            if let Some(set) = self.clients_by_channel.get_mut(&old_ch) {
                set.remove(id);
                if set.is_empty() {
                    self.clients_by_channel.remove(&old_ch);
                }
            }
        }
    }

    fn listener_index_add(&mut self, id: ScopedSessionId, channel_id: u32) {
        let channel_key = ScopedChannelId::new(id.server_id().to_owned(), channel_id);
        self.listeners_by_channel
            .entry(channel_key)
            .or_default()
            .insert(id);
    }

    fn listener_index_remove_channel(&mut self, id: &ScopedSessionId, channel_id: u32) {
        let channel_key = ScopedChannelId::new(id.server_id().to_owned(), channel_id);
        if let Some(set) = self.listeners_by_channel.get_mut(&channel_key) {
            set.remove(id);
            if set.is_empty() {
                self.listeners_by_channel.remove(&channel_key);
            }
        }
    }

    fn listener_index_remove_all(&mut self, id: &ScopedSessionId) {
        self.listeners_by_channel.retain(|_, set| {
            set.remove(id);
            !set.is_empty()
        });
    }
}

impl ClientRepository {
    pub fn new(local_node_id: u16, log_max_entries: usize) -> Self {
        let log_max_entries = log_max_entries.max(1);
        let (tx, _) = broadcast::channel(projection_broadcast_capacity(log_max_entries));
        let register = Arc::new(AsyncRwLock::new(ClientRegister {
            local_clients: HashMap::new(),
            authenticated_local_clients: HashSet::new(),
            local_log: VecDeque::new(),
            version: 0,
            clients_by_channel: HashMap::new(),
            client_channel: HashMap::new(),
            listeners_by_channel: HashMap::new(),
        }));
        let versions = Arc::new(ClientVersionIndex::default());
        let remote_registers = Arc::new(AsyncRwLock::new(HashMap::new()));
        let deferred_commit_pending = Arc::new(AtomicUsize::new(0));
        let deferred_commit_tx = tokio::runtime::Handle::try_current().ok().map(|handle| {
            let (deferred_tx, mut deferred_rx) = mpsc::unbounded_channel::<DeferredClientCommit>();
            let register = Arc::clone(&register);
            let tx = tx.clone();
            let pending = Arc::clone(&deferred_commit_pending);
            let versions = Arc::clone(&versions);
            handle.spawn(async move {
                while let Some(commit) = deferred_rx.recv().await {
                    let broadcast = {
                        let mut register = register.write().await;
                        Self::commit_operation_inner(
                            &mut register,
                            local_node_id,
                            log_max_entries,
                            &versions,
                            commit.op,
                            commit.channel_version_dep,
                        )
                    };
                    if let Some(broadcast) = broadcast {
                        let _ = tx.send(broadcast);
                    }
                    pending.fetch_sub(1, Ordering::AcqRel);
                }
            });
            deferred_tx
        });
        ClientRepository {
            local_node_id,
            log_max_entries,
            register,
            remote_registers,
            clients_by_host: ParkingRwLock::new(HashMap::new()),
            clients_by_udp_address: ParkingRwLock::new(HashMap::new()),
            allocation_pointers: ParkingMutex::new(HashMap::new()),
            free_ids: ParkingMutex::new(HashMap::new()),
            tx,
            deferred_commit_tx,
            deferred_commit_pending,
            versions,
            authenticated_client_counts: AuthenticatedClientCounts::default(),
        }
    }

    /// The node ID of this repository.
    pub fn local_node_id(&self) -> u16 {
        self.local_node_id
    }

    /// Return the number of authenticated local and replicated clients in a
    /// virtual server without materializing a repository snapshot.
    pub fn authenticated_client_count_in_server(&self, server_id: &str) -> u64 {
        self.authenticated_client_counts.get(server_id)
    }

    fn apply_authenticated_client_count_change(
        &self,
        change: Option<AuthenticatedClientCountChange>,
    ) {
        match change {
            Some(AuthenticatedClientCountChange::Added(server_id)) => {
                self.authenticated_client_counts.increment(&server_id);
            }
            Some(AuthenticatedClientCountChange::Removed(server_id)) => {
                self.authenticated_client_counts.decrement(&server_id);
            }
            None => {}
        }
    }

    /// Atomically reserve one authenticated-client slot for a local session.
    /// The reservation is owned by the repository and is released when the
    /// session is removed, including authentication cancellation paths.
    pub async fn try_reserve_authenticated_client_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
        max_users: u64,
    ) -> bool {
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        let mut register = self.register.write().await;
        if !register.local_clients.contains_key(&scoped_id) {
            return false;
        }
        if register.authenticated_local_clients.contains(&scoped_id) {
            return true;
        }
        if !self
            .authenticated_client_counts
            .try_increment_below(server_id, max_users)
        {
            return false;
        }
        register.authenticated_local_clients.insert(scoped_id);
        true
    }

    pub(crate) async fn release_authenticated_client_reservation_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
    ) {
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        let mut register = self.register.write().await;
        if register.authenticated_local_clients.remove(&scoped_id) {
            self.authenticated_client_counts.decrement(server_id);
        }
    }

    async fn get_remote_register(
        &self,
        node_id: u16,
    ) -> Option<Arc<AsyncRwLock<RemoteClientRegister>>> {
        if node_id == self.local_node_id {
            return None;
        }
        self.remote_registers.read().await.get(&node_id).cloned()
    }

    async fn get_or_create_remote_register(
        &self,
        node_id: u16,
    ) -> Arc<AsyncRwLock<RemoteClientRegister>> {
        if node_id == self.local_node_id {
            panic!("remote register requested for local node");
        }
        {
            let registers = self.remote_registers.read().await;
            if let Some(register) = registers.get(&node_id) {
                return Arc::clone(register);
            }
        }
        let mut registers = self.remote_registers.write().await;
        Arc::clone(
            registers
                .entry(node_id)
                .or_insert_with(|| Arc::new(AsyncRwLock::new(RemoteClientRegister::new()))),
        )
    }

    async fn remote_register_snapshots(
        &self,
    ) -> Vec<(u16, Arc<AsyncRwLock<RemoteClientRegister>>)> {
        self.remote_registers
            .read()
            .await
            .iter()
            .map(|(&node_id, register)| (node_id, Arc::clone(register)))
            .collect()
    }

    fn allocate_local_session_id(&self, server_id: &str) -> u32 {
        {
            let mut free_ids_guard = self.free_ids.lock();
            if let Some(free_ids) = free_ids_guard.get_mut(server_id) {
                if let Some(free_id) = free_ids.iter().next().copied() {
                    free_ids.remove(&free_id);
                    return free_id;
                }
            }
        }
        let mut pointers = self.allocation_pointers.lock();
        let allocation_pointer = pointers.entry(server_id.to_owned()).or_insert(0);
        if self.local_node_id == 0 && *allocation_pointer == 0 {
            *allocation_pointer = 1;
        }
        let id = *allocation_pointer;

        if id > MAX_LOCAL_SESSION_ID {
            panic!(
                "Exceeded maximum number of local session IDs for server_id={server_id}. Consider rearranging the allocation strategy"
            );
        }

        *allocation_pointer += 1;
        id
    }

    fn release_local_session_id(&self, server_id: &str, local_session_id: u32) {
        self.free_ids
            .lock()
            .entry(server_id.to_owned())
            .or_default()
            .insert(local_session_id);
    }

    pub async fn move_local_client_to_server(
        &self,
        old_server_id: &str,
        old_id: ClientSessionIdentifier,
        new_server_id: &str,
    ) -> Option<ClientSessionIdentifier> {
        if old_server_id == new_server_id {
            return Some(old_id);
        }

        let old_scoped_id = ScopedSessionId::new(old_server_id.to_owned(), old_id);
        let moved = {
            let mut register = self.register.write().await;
            let mut client_by_udp_address_guard = self.clients_by_udp_address.write();
            let mut client_by_host_guard = self.clients_by_host.write();
            let new_local_id = self.allocate_local_session_id(new_server_id);
            let new_id = ClientSessionIdentifier::new(self.local_node_id, new_local_id).ok()?;
            let new_scoped_id = ScopedSessionId::new(new_server_id.to_owned(), new_id);

            let client = register.local_clients.remove(&old_scoped_id)?;
            register.channel_index_remove(&old_scoped_id);
            register.listener_index_remove_all(&old_scoped_id);
            if register.authenticated_local_clients.remove(&old_scoped_id) {
                self.authenticated_client_counts.decrement(old_server_id);
                self.authenticated_client_counts.increment(new_server_id);
                register
                    .authenticated_local_clients
                    .insert(new_scoped_id.clone());
            }

            let tcp_address = client.get_tcp_address();
            if let Some(set) = client_by_host_guard.get_mut(&tcp_address.ip()) {
                set.remove(&old_scoped_id);
                set.insert(new_scoped_id.clone());
            }

            let stale_udp: Vec<UdpBindingKey> = client_by_udp_address_guard
                .iter()
                .filter_map(|(key, scoped)| (*scoped == old_scoped_id).then_some(*key))
                .collect();
            for key in stale_udp {
                client_by_udp_address_guard.insert(key, new_scoped_id.clone());
            }

            client.set_scoped_identity(new_server_id.to_owned(), new_id);
            register
                .local_clients
                .insert(new_scoped_id.clone(), Arc::clone(&client));
            register.channel_index_insert(new_scoped_id, 0);
            (new_id, client)
        };

        if moved.1.is_published() {
            tracing::warn!(
                old_server_id,
                new_server_id,
                session = u32::from(old_id),
                "moved already-published local client across server scopes"
            );
        } else {
            self.release_local_session_id(old_server_id, old_id.local_session_id);
        }

        Some(moved.0)
    }

    pub async fn allocate_local_client(
        &self,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
    ) -> Arc<Box<Client>> {
        self.allocate_local_client_in_server(
            DEFAULT_SERVER_ID,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
            None,
            false,
        )
        .await
    }

    pub async fn allocate_local_client_in_server(
        &self,
        server_id: impl Into<String>,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
        tls_ja4: Option<String>,
        uses_proxy_protocol: bool,
    ) -> Arc<Box<Client>> {
        let server_id = server_id.into();
        let mut register = self.register.write().await;
        let mut client_by_udp_address_guard = self.clients_by_udp_address.write();
        let mut client_by_host_guard = self.clients_by_host.write();

        let id = self.allocate_local_session_id(&server_id);
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let client_instance_id = next_client_instance_id(self.local_node_id);
        let scoped_id = ScopedSessionId::new(server_id.clone(), client_identifier);
        let client = Client::new_local_in_server_with_instance_id(
            server_id,
            client_identifier,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
            tls_ja4,
            uses_proxy_protocol,
            client_instance_id,
        );

        let client = Arc::new(client);

        register
            .local_clients
            .insert(scoped_id.clone(), Arc::clone(&client));
        register.channel_index_insert(scoped_id.clone(), 0); // root channel until auth sets it

        if let Some(udp_address) = udp_address {
            client_by_udp_address_guard.insert(
                UdpBindingKey::scoped(local_address, udp_address),
                scoped_id.clone(),
            );
        }

        if let Some(set) = client_by_host_guard.get_mut(&tcp_address.ip()) {
            set.insert(scoped_id);
        } else {
            let mut set = HashSet::new();
            set.insert(scoped_id);
            client_by_host_guard.insert(tcp_address.ip(), set);
        }

        // NOTE: AddClient log entry is deferred until the client
        // authenticates.  See `publish_client()`.

        tracing::info!(
            server_id = %client.server_id(),
            session = u32::from(client.get_session_id()),
            client_instance_id = client.client_instance_id(),
            transport = ?client.transport_kind(),
            real_ip = %client.get_real_ip_address(),
            tcp_addr = %client.get_tcp_address(),
            udp_addr = ?client.get_udp_address(),
            local_addr = %client.get_local_address(),
            "client connected"
        );

        client
    }

    pub async fn allocate_web_client(
        &self,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: tokio::sync::mpsc::Sender<shitspeak_messages::messages::Message>,
    ) -> Arc<Box<Client>> {
        self.allocate_web_client_in_server(
            DEFAULT_SERVER_ID,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
        )
        .await
    }

    pub async fn allocate_web_client_in_server(
        &self,
        server_id: impl Into<String>,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: tokio::sync::mpsc::Sender<shitspeak_messages::messages::Message>,
    ) -> Arc<Box<Client>> {
        let server_id = server_id.into();
        let mut register = self.register.write().await;
        let mut client_by_host_guard = self.clients_by_host.write();

        let id = self.allocate_local_session_id(&server_id);
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let client_instance_id = next_client_instance_id(self.local_node_id);
        let scoped_id = ScopedSessionId::new(server_id.clone(), client_identifier);
        let client = Client::new_web_gateway_in_server_with_instance_id(
            server_id,
            client_identifier,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
            client_instance_id,
        );

        let client = Arc::new(client);

        register
            .local_clients
            .insert(scoped_id.clone(), Arc::clone(&client));
        register.channel_index_insert(scoped_id.clone(), 0);

        client_by_host_guard
            .entry(tcp_address.ip())
            .or_default()
            .insert(scoped_id);

        tracing::info!(
            server_id = %client.server_id(),
            session = u32::from(client.get_session_id()),
            client_instance_id = client.client_instance_id(),
            transport = ?client.transport_kind(),
            real_ip = %client.get_real_ip_address(),
            tcp_addr = %client.get_tcp_address(),
            local_addr = %client.get_local_address(),
            "client connected"
        );

        client
    }

    pub async fn allocate_moq_client_in_server(
        &self,
        server_id: impl Into<String>,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: tokio::sync::mpsc::Sender<shitspeak_messages::messages::Message>,
    ) -> Arc<Box<Client>> {
        let server_id = server_id.into();
        let mut register = self.register.write().await;
        let mut client_by_host_guard = self.clients_by_host.write();

        let id = self.allocate_local_session_id(&server_id);
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let client_instance_id = next_client_instance_id(self.local_node_id);
        let scoped_id = ScopedSessionId::new(server_id.clone(), client_identifier);
        let client = Client::new_moq_gateway_in_server_with_instance_id(
            server_id,
            client_identifier,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
            client_instance_id,
        );

        let client = Arc::new(client);

        register
            .local_clients
            .insert(scoped_id.clone(), Arc::clone(&client));
        register.channel_index_insert(scoped_id.clone(), 0);

        client_by_host_guard
            .entry(tcp_address.ip())
            .or_default()
            .insert(scoped_id);

        tracing::info!(
            server_id = %client.server_id(),
            session = u32::from(client.get_session_id()),
            client_instance_id = client.client_instance_id(),
            transport = ?client.transport_kind(),
            real_ip = %client.get_real_ip_address(),
            tcp_addr = %client.get_tcp_address(),
            local_addr = %client.get_local_address(),
            "client connected"
        );

        client
    }

    /// Emit the `AddClient` log entry for a client that has completed
    /// authentication.  Sets the `published` flag so that future
    /// `remove_client` calls will emit a corresponding `RemoveClient`.
    pub async fn publish_client(&self, id: ClientSessionIdentifier) {
        self.publish_client_in_server(DEFAULT_SERVER_ID, id).await;
    }

    pub async fn publish_client_in_server(&self, server_id: &str, id: ClientSessionIdentifier) {
        self.wait_for_deferred_commits().await;
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        let broadcast = {
            let mut register = self.register.write().await;
            let Some(client) = register.local_clients.get(&scoped_id).cloned() else {
                return;
            };
            if client.is_published() {
                return;
            }
            if client.is_authenticated()
                && register
                    .authenticated_local_clients
                    .insert(scoped_id.clone())
            {
                self.authenticated_client_counts.increment(server_id);
            }
            register.sync_local_client_indexes(&scoped_id, &client);
            let initial_state =
                ClientGlobalStateDelta::from_global_state(&client.read_global_state());
            let broadcast = Self::commit_operation_inner(
                &mut register,
                self.local_node_id,
                self.log_max_entries,
                &self.versions,
                ClientStateOperation::AddClient {
                    server_id: server_id.to_owned(),
                    session_id: id,
                    client_instance_id: client.client_instance_id(),
                    real_ip: client.get_real_ip_address(),
                    tcp_addr: client.get_tcp_address(),
                    udp_addr: client.get_udp_address(),
                    local_addr: client.get_tcp_address(),
                    cert_hash: client
                        .get_certificate_hash()
                        .map(bytes::Bytes::copy_from_slice),
                    login_time: client.get_login_time(),
                    initial_state,
                },
                None,
            );
            client.set_published(true);
            broadcast
        };
        if let Some(broadcast) = broadcast {
            let _ = self.tx.send(broadcast);
        }
    }

    pub async fn add_remote_client(&self, id: ClientSessionIdentifier, client: Arc<Box<Client>>) {
        let node_id = client.get_node_id();
        if node_id == self.local_node_id {
            panic!("Not supposed to add a remote client with the local node ID");
        }
        let server_id = client.server_id();
        let scoped_id = ScopedSessionId::new(server_id.clone(), id);
        let remote_register = self.get_or_create_remote_register(node_id).await;
        let mut register = remote_register.write().await;
        let channel_id = client.get_current_channel_id();
        let listener_channels = client.get_listening_channel_ids();
        if register.clients.insert(scoped_id.clone(), client).is_none() {
            self.authenticated_client_counts.increment(&server_id);
        }
        register.channel_index_insert(scoped_id.clone(), channel_id);
        for channel_id in listener_channels {
            register.listener_index_add(scoped_id.clone(), channel_id);
        }
        // NOTE: remote clients are intentionally NOT added to the local
        // channel index — voice routing only targets local clients (remote
        // clients receive audio via S2S from their owning node).
    }

    pub async fn remove_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        self.remove_client_in_server(DEFAULT_SERVER_ID, id).await
    }

    pub async fn remove_client_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
    ) -> Option<Arc<Box<Client>>> {
        self.remove_client_in_server_inner(server_id, id, None, None, false, None)
            .await
    }

    pub async fn remove_client_instance_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
        client_instance_id: ClientInstanceId,
    ) -> Option<Arc<Box<Client>>> {
        self.remove_client_in_server_inner(
            server_id,
            id,
            None,
            None,
            false,
            Some(client_instance_id),
        )
        .await
    }

    pub(crate) async fn remove_client_in_server_with_metadata(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
        actor: Option<ClientSessionIdentifier>,
        reason: Option<String>,
        ban: bool,
    ) -> Option<Arc<Box<Client>>> {
        self.remove_client_in_server_inner(server_id, id, actor, reason, ban, None)
            .await
    }

    async fn remove_client_in_server_inner(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
        actor: Option<ClientSessionIdentifier>,
        reason: Option<String>,
        ban: bool,
        expected_client_instance_id: Option<ClientInstanceId>,
    ) -> Option<Arc<Box<Client>>> {
        self.wait_for_deferred_commits().await;
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        let local_client = {
            let mut register = self.register.write().await;
            let mut client_by_udp_address_guard = self.clients_by_udp_address.write();
            let mut client_by_host_guard = self.clients_by_host.write();

            if let Some(expected) = expected_client_instance_id {
                if let Some(client) = register.local_clients.get(&scoped_id) {
                    if client.client_instance_id() != expected {
                        tracing::debug!(
                            server_id,
                            session = u32::from(id),
                            expected_client_instance_id = expected,
                            current_client_instance_id = client.client_instance_id(),
                            "skipping stale client removal for reused session"
                        );
                        return None;
                    }
                }
            }

            if let Some(client) = register.local_clients.remove(&scoped_id) {
                register.channel_index_remove(&scoped_id);
                register.listener_index_remove_all(&scoped_id);
                if register.authenticated_local_clients.remove(&scoped_id) {
                    self.authenticated_client_counts.decrement(server_id);
                }

                // Remove any UDP address dynamically bound to this session (may
                // differ from the initial udp_address field if the client's port
                // was discovered later via IP-fallback matching).
                let stale_udp: Vec<UdpBindingKey> = client_by_udp_address_guard
                    .iter()
                    .filter_map(|(k, v)| if *v == scoped_id { Some(*k) } else { None })
                    .collect();
                for key in stale_udp {
                    client_by_udp_address_guard.remove(&key);
                }

                let tcp_address = client.get_tcp_address();

                if let Some(set) = client_by_host_guard.get_mut(&tcp_address.ip()) {
                    set.remove(&scoped_id);
                    if set.is_empty() {
                        client_by_host_guard.remove(&tcp_address.ip());
                    }
                }

                Some(client)
            } else {
                None
            }
        };

        let client = if let Some(client) = local_client {
            client
        } else {
            let remote_register = self.get_remote_register(id.node_id).await?;
            let removed = {
                let mut register = remote_register.write().await;
                if let Some(expected) = expected_client_instance_id {
                    if let Some(client) = register.clients.get(&scoped_id) {
                        if client.client_instance_id() != expected {
                            tracing::debug!(
                                server_id,
                                session = u32::from(id),
                                expected_client_instance_id = expected,
                                current_client_instance_id = client.client_instance_id(),
                                "skipping stale remote client removal for reused session"
                            );
                            return None;
                        }
                    }
                }
                let removed = register.clients.remove(&scoped_id);
                if removed.is_some() {
                    self.authenticated_client_counts.decrement(server_id);
                }
                register.channel_index_remove(&scoped_id);
                register.listener_index_remove_all(&scoped_id);
                removed
            };
            removed?
        };
        client.mark_removed();

        if client.get_node_id() == self.local_node_id && client.is_published() {
            if self
                .commit_operation(
                    ClientStateOperation::RemoveClient {
                        server_id: server_id.to_owned(),
                        session_id: id,
                        client_instance_id: client.client_instance_id(),
                        actor,
                        reason,
                        ban,
                    },
                    None,
                )
                .await
                .is_some()
            {
                self.release_local_session_id(server_id, id.local_session_id);
            }
        } else if client.get_node_id() == self.local_node_id {
            self.release_local_session_id(server_id, id.local_session_id);
        }

        tracing::info!(
            server_id,
            session = u32::from(id),
            client_instance_id = client.client_instance_id(),
            transport = ?client.transport_kind(),
            user_id = ?client.get_user_id(),
            display_name = ?client.display_name_opt(),
            channel_id = client.get_current_channel_id(),
            "client disconnected"
        );

        Some(client)
    }

    /// Reset an origin after LSDB admits a strictly newer boot epoch.
    /// Duplicate same-epoch reset notifications are intentionally no-ops so
    /// they cannot erase operations already accepted in that epoch.
    pub(crate) async fn reset_clients_from_node(&self, node_id: u16, new_epoch: u64) {
        if node_id == self.local_node_id {
            panic!("Not supposed to clear clients from the local node");
        }

        let remote_register = self.get_or_create_remote_register(node_id).await;
        let mut register = remote_register.write().await;
        match register.epoch {
            Some(epoch) if new_epoch < epoch => {
                tracing::warn!(
                    node_id,
                    new_epoch,
                    current_epoch = epoch,
                    "ignoring stale remote client epoch reset"
                );
                return;
            }
            Some(epoch) if new_epoch == epoch => return,
            _ => {}
        }
        let removals = register
            .clients
            .iter()
            .map(|(id, client)| {
                (
                    id.clone(),
                    client.is_published(),
                    client.client_instance_id(),
                )
            })
            .collect();
        let previous_counts = authenticated_counts_by_server(&register.clients);
        let base_version = register.version;
        register.clear_materialized_state();
        self.authenticated_client_counts
            .replace_remote_counts(&previous_counts, &HashMap::new());
        register.epoch = Some(new_epoch);
        register.epoch_version_floor = 0;
        register.materialized = true;
        self.broadcast_origin_removals(node_id, removals, base_version);
    }

    /// Remove the visible transient state for an offline origin while
    /// retaining its epoch fence against delayed packets.
    pub(crate) async fn remove_clients_from_node(&self, node_id: u16) {
        if node_id == self.local_node_id {
            panic!("Not supposed to clear clients from the local node");
        }
        let Some(remote_register) = self.get_remote_register(node_id).await else {
            return;
        };
        let mut register = remote_register.write().await;
        let removals = register
            .clients
            .iter()
            .map(|(id, client)| {
                (
                    id.clone(),
                    client.is_published(),
                    client.client_instance_id(),
                )
            })
            .collect();
        let previous_counts = authenticated_counts_by_server(&register.clients);
        let base_version = register.version;
        let epoch_version_floor = register
            .pending_ops
            .back()
            .map(|(entry, _)| entry.version)
            .unwrap_or(base_version)
            .max(base_version);
        register.clear_materialized_state();
        self.authenticated_client_counts
            .replace_remote_counts(&previous_counts, &HashMap::new());
        register.epoch_version_floor = register.epoch_version_floor.max(epoch_version_floor);
        register.materialized = false;
        self.broadcast_origin_removals(node_id, removals, base_version);
    }

    /// Legacy un-fenced removal retained for local consumers and tests.
    pub async fn clear_clients_from_node(&self, node_id: u16) {
        self.remove_clients_from_node(node_id).await;
    }

    fn broadcast_origin_removals(
        &self,
        node_id: u16,
        removals: Vec<(ScopedSessionId, bool, ClientInstanceId)>,
        base_version: u64,
    ) {
        if base_version > 0 || removals.iter().any(|(_, published, _)| *published) {
            let entry = Arc::new(ClientStateLogEntry {
                version: 1,
                node_id,
                timestamp: chrono::Utc::now().timestamp_millis(),
                channel_version_dep: None,
                op: ClientStateOperation::ResetNode {
                    server_id: crate::types::default_server_id(),
                },
            });
            let _ = self.tx.send(Arc::new(ClientStateBroadcastPayload::new(
                entry,
                HashMap::from([(node_id, 0)]),
            )));
        }
    }

    pub async fn get_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        self.get_client_in_server(DEFAULT_SERVER_ID, id).await
    }

    pub async fn get_client_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
    ) -> Option<Arc<Box<Client>>> {
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        if id.node_id == self.local_node_id {
            self.register
                .read()
                .await
                .local_clients
                .get(&scoped_id)
                .cloned()
        } else {
            self.get_remote_register(id.node_id)
                .await?
                .read()
                .await
                .clients
                .get(&scoped_id)
                .cloned()
        }
    }

    pub async fn get_local_clients_by_ids_in_server(
        &self,
        server_id: &str,
        ids: &[ClientSessionIdentifier],
    ) -> Vec<Option<Arc<Box<Client>>>> {
        let register = self.register.read().await;
        ids.iter()
            .map(|id| {
                if id.get_node_id() != self.local_node_id {
                    return None;
                }
                let scoped_id = ScopedSessionId::new(server_id.to_owned(), *id);
                register.local_clients.get(&scoped_id).cloned()
            })
            .collect()
    }

    /// Look up a client by their UDP socket address.
    pub async fn get_client_by_udp_address(&self, addr: &SocketAddr) -> Option<Arc<Box<Client>>> {
        self.get_client_by_udp_address_key(UdpBindingKey::legacy(*addr))
            .await
    }

    pub async fn get_client_by_udp_endpoint(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<Arc<Box<Client>>> {
        let scoped = self
            .get_client_by_udp_address_key(UdpBindingKey::scoped(local_addr, remote_addr))
            .await;
        if scoped.is_some() {
            scoped
        } else {
            self.get_client_by_udp_address_key(UdpBindingKey::legacy(remote_addr))
                .await
        }
    }

    async fn get_client_by_udp_address_key(&self, key: UdpBindingKey) -> Option<Arc<Box<Client>>> {
        let id = {
            let by_udp = self.clients_by_udp_address.read();
            by_udp.get(&key)?.clone()
        };
        self.register.read().await.local_clients.get(&id).cloned()
    }

    /// Remove a specific UDP address binding.  Called when decrypt fails for a
    /// cached address so the UDP process loop can re-probe via IP.
    pub fn unbind_client_udp_address(&self, addr: &SocketAddr) {
        self.unbind_client_udp_address_key(UdpBindingKey::legacy(*addr));
    }

    pub fn unbind_client_udp_endpoint(&self, local_addr: SocketAddr, remote_addr: SocketAddr) {
        self.unbind_client_udp_address_key(UdpBindingKey::scoped(local_addr, remote_addr));
    }

    fn unbind_client_udp_address_key(&self, key: UdpBindingKey) {
        let removed_id = {
            let mut by_udp = self.clients_by_udp_address.write();
            by_udp.remove(&key)
        };
        if let Some(id) = removed_id {
            // Best-effort: clear the corresponding Client field so the
            // routing layer's `get_udp_address()` returns `None` and falls
            // back to the TCP tunnel until the next encrypted UDP packet
            // re-binds. Use a non-blocking try-read; if the register lock is
            // contended we'll just leave the stale field in place — the
            // address-to-session map (the source of truth for inbound
            // matching) was already cleared above.
            if let Ok(reg) = self.register.try_read() {
                if let Some(client) = reg.local_clients.get(&id) {
                    client.set_udp_address(None);
                }
            }
        }
    }

    /// Bind/update the UDP address for a client session for fast future lookup.
    pub async fn bind_client_udp_address(&self, id: ClientSessionIdentifier, addr: SocketAddr) {
        self.bind_client_udp_address_in_server(DEFAULT_SERVER_ID, id, addr)
            .await;
    }

    pub async fn bind_client_udp_address_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
        addr: SocketAddr,
    ) {
        self.bind_client_udp_endpoint_in_server(server_id, id, None, addr)
            .await;
    }

    pub async fn bind_client_udp_endpoint_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
        local_addr: Option<SocketAddr>,
        remote_addr: SocketAddr,
    ) {
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        let key = match local_addr {
            Some(local_addr) => UdpBindingKey::scoped(local_addr, remote_addr),
            None => UdpBindingKey::legacy(remote_addr),
        };
        {
            let mut by_udp = self.clients_by_udp_address.write();
            // Remove stale mappings for this session to keep map one-to-one.
            let stale: Vec<UdpBindingKey> = by_udp
                .iter()
                .filter_map(|(k, v)| if *v == scoped_id { Some(*k) } else { None })
                .collect();
            for old in stale {
                by_udp.remove(&old);
            }
            by_udp.insert(key, scoped_id.clone());
        }
        // Mirror the binding onto the Client itself so the routing layer's
        // `client.get_udp_address()` returns it. Without this, `flush_voice_batch`
        // would always fall back to the TCP tunnel even though we just
        // confirmed the client is reachable by UDP.
        let register = self.register.read().await;
        if let Some(client) = register.local_clients.get(&scoped_id) {
            client.set_udp_address(Some(remote_addr));
        }
    }

    /// Look up clients sharing the same IP (for UDP packet matching fallback).
    pub async fn get_clients_by_ip(&self, ip: &IpAddr) -> Vec<Arc<Box<Client>>> {
        let ids = {
            let by_host = self.clients_by_host.read();
            match by_host.get(ip) {
                Some(ids) => ids.iter().cloned().collect::<Vec<_>>(),
                None => return Vec::new(),
            }
        };
        let register = self.register.read().await;
        ids.iter()
            .filter_map(|id| register.local_clients.get(id).cloned())
            .collect()
    }

    // ── Broadcast helpers ─────────────────────────────────────────────────

    /// Send `message` to every connected client.
    pub async fn broadcast_all(&self, message: &shitspeak_messages::messages::Message) {
        self.broadcast_all_in_server(DEFAULT_SERVER_ID, message)
            .await;
    }

    pub async fn broadcast_all_in_server(
        &self,
        server_id: &str,
        message: &shitspeak_messages::messages::Message,
    ) {
        let clients: Vec<_> = {
            let register = self.register.read().await;
            register
                .local_clients()
                .filter(|client| client.server_id() == server_id)
                .cloned()
                .collect()
        };

        for client in clients {
            if let Err(e) = client.enqueue_proto_message(message).await {
                client.in_tracing_scope(|| tracing::warn!("broadcast_all enqueue error: {e}"));
            }
        }
    }

    /// Send `message` to every client except `exclude`.
    pub async fn broadcast_except(
        &self,
        exclude: ClientSessionIdentifier,
        message: &shitspeak_messages::messages::Message,
    ) {
        self.broadcast_except_in_server(DEFAULT_SERVER_ID, exclude, message)
            .await;
    }

    pub async fn broadcast_except_in_server(
        &self,
        server_id: &str,
        exclude: ClientSessionIdentifier,
        message: &shitspeak_messages::messages::Message,
    ) {
        let exclude_key = ScopedSessionId::new(server_id.to_owned(), exclude);
        let clients: Vec<_> = {
            let register = self.register.read().await;
            register
                .local_clients
                .iter()
                .filter(|(id, _)| **id != exclude_key && id.server_id() == server_id)
                .map(|(_, client)| Arc::clone(client))
                .collect()
        };

        for client in clients {
            if let Err(e) = client.enqueue_proto_message(message).await {
                client.in_tracing_scope(|| tracing::warn!("broadcast_except enqueue error: {e}"));
            }
        }
    }

    /// Send a batch of messages to every client except `exclude`, using a
    /// single write per client.
    pub async fn broadcast_batch_except(
        &self,
        exclude: ClientSessionIdentifier,
        messages: &[shitspeak_messages::messages::Message],
    ) {
        self.broadcast_batch_except_in_server(DEFAULT_SERVER_ID, exclude, messages)
            .await;
    }

    pub async fn broadcast_batch_except_in_server(
        &self,
        server_id: &str,
        exclude: ClientSessionIdentifier,
        messages: &[shitspeak_messages::messages::Message],
    ) {
        let exclude_key = ScopedSessionId::new(server_id.to_owned(), exclude);
        let clients: Vec<_> = {
            let register = self.register.read().await;
            register
                .local_clients
                .iter()
                .filter(|(id, _)| **id != exclude_key && id.server_id() == server_id)
                .map(|(_, client)| Arc::clone(client))
                .collect()
        };

        for client in clients {
            if let Err(e) = client.enqueue_proto_message_batch(messages).await {
                client.in_tracing_scope(|| {
                    tracing::warn!("broadcast_batch_except enqueue error: {e}")
                });
            }
        }
    }

    /// Return a snapshot of all currently-connected clients (including unauthenticated).
    pub async fn get_all_clients(&self) -> Vec<Arc<Box<Client>>> {
        let mut clients: Vec<_> = self
            .register
            .read()
            .await
            .local_clients()
            .cloned()
            .collect();
        for (_, register) in self.remote_register_snapshots().await {
            clients.extend(register.read().await.clients.values().cloned());
        }
        clients
    }

    pub async fn get_all_clients_in_server(&self, server_id: &str) -> Vec<Arc<Box<Client>>> {
        let mut clients: Vec<_> = self
            .register
            .read()
            .await
            .local_clients()
            .filter(|client| client.server_id() == server_id)
            .cloned()
            .collect();
        for (_, register) in self.remote_register_snapshots().await {
            clients.extend(
                register
                    .read()
                    .await
                    .clients
                    .values()
                    .filter(|client| client.server_id() == server_id)
                    .cloned(),
            );
        }
        clients
    }

    pub async fn get_clients_in_channels_or_listeners_in_server(
        &self,
        server_id: &str,
        channel_ids: &HashSet<u32>,
    ) -> Vec<Arc<Box<Client>>> {
        if channel_ids.is_empty() {
            return Vec::new();
        }

        let mut clients = Vec::new();
        let mut seen = HashSet::new();
        {
            let register = self.register.read().await;
            append_indexed_clients(
                &register.local_clients,
                &register.clients_by_channel,
                &register.listeners_by_channel,
                server_id,
                channel_ids,
                &mut seen,
                &mut clients,
            );
        }
        for (_, register) in self.remote_register_snapshots().await {
            let register = register.read().await;
            append_indexed_clients(
                &register.clients,
                &register.clients_by_channel,
                &register.listeners_by_channel,
                server_id,
                channel_ids,
                &mut seen,
                &mut clients,
            );
        }

        clients
    }

    /// Return a snapshot of locally connected clients.
    pub async fn get_local_clients(&self) -> Vec<Arc<Box<Client>>> {
        self.register
            .read()
            .await
            .local_clients()
            .cloned()
            .collect()
    }

    pub async fn get_local_clients_in_server(&self, server_id: &str) -> Vec<Arc<Box<Client>>> {
        self.register
            .read()
            .await
            .local_clients()
            .filter(|client| client.server_id() == server_id)
            .cloned()
            .collect()
    }

    /// Return **local** clients currently in `channel_id` via the channel
    /// index. Remote clients are not tracked here — voice for them is
    /// delivered to their owning node over S2S.
    pub async fn get_local_clients_in_channel(&self, channel_id: u32) -> Vec<Arc<Box<Client>>> {
        self.get_local_clients_in_channel_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn get_local_clients_in_channel_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> Vec<Arc<Box<Client>>> {
        let register = self.register.read().await;
        let channel_key = ScopedChannelId::new(server_id.to_owned(), channel_id);
        let ids = match register.clients_by_channel.get(&channel_key) {
            Some(s) => s.iter().cloned().collect::<Vec<_>>(),
            None => return Vec::new(),
        };
        ids.iter()
            .filter_map(|id| register.local_clients.get(id).cloned())
            .collect()
    }

    /// Return whether any materialized client, local or remote, is currently
    /// in `channel_id`. This intentionally does not use the local voice-routing
    /// channel index, because maintenance tasks such as temporary-channel
    /// reaping must account for cross-node occupants too.
    pub async fn has_client_in_channel(&self, channel_id: u32) -> bool {
        self.has_client_in_channel_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn has_client_in_channel_in_server(&self, server_id: &str, channel_id: u32) -> bool {
        if self.register.read().await.local_clients().any(|client| {
            client.server_id() == server_id && client.get_current_channel_id() == channel_id
        }) {
            return true;
        }
        for (_, register) in self.remote_register_snapshots().await {
            if register.read().await.clients.values().any(|client| {
                client.server_id() == server_id && client.get_current_channel_id() == channel_id
            }) {
                return true;
            }
        }
        false
    }

    /// Return **local** clients currently in any of the given `channel_ids`
    /// in a single lock acquisition.
    pub async fn get_local_clients_in_channels(
        &self,
        channel_ids: &[u32],
    ) -> Vec<Arc<Box<Client>>> {
        self.get_local_clients_in_channels_in_server(DEFAULT_SERVER_ID, channel_ids)
            .await
    }

    pub async fn get_local_clients_in_channels_in_server(
        &self,
        server_id: &str,
        channel_ids: &[u32],
    ) -> Vec<Arc<Box<Client>>> {
        let register = self.register.read().await;
        let mut result = Vec::new();
        for &ch_id in channel_ids {
            let channel_key = ScopedChannelId::new(server_id.to_owned(), ch_id);
            if let Some(ids) = register.clients_by_channel.get(&channel_key) {
                for id in ids {
                    if let Some(c) = register.local_clients.get(id) {
                        result.push(c.clone());
                    }
                }
            }
        }
        result
    }

    /// Return **local** clients that have subscribed to listen to `channel_id`.
    pub async fn get_local_listeners_for_channel(&self, channel_id: u32) -> Vec<Arc<Box<Client>>> {
        self.get_local_listeners_for_channel_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
    }

    pub async fn get_local_listeners_for_channel_in_server(
        &self,
        server_id: &str,
        channel_id: u32,
    ) -> Vec<Arc<Box<Client>>> {
        let register = self.register.read().await;
        let channel_key = ScopedChannelId::new(server_id.to_owned(), channel_id);
        let ids = match register.listeners_by_channel.get(&channel_key) {
            Some(s) => s.iter().cloned().collect::<Vec<_>>(),
            None => return Vec::new(),
        };
        ids.iter()
            .filter_map(|id| register.local_clients.get(id).cloned())
            .collect()
    }

    /// Return **local** clients that have subscribed to listen to any of the
    /// given `channel_ids` in a single lock acquisition.
    pub async fn get_local_listeners_for_channels(
        &self,
        channel_ids: &[u32],
    ) -> Vec<Arc<Box<Client>>> {
        self.get_local_listeners_for_channels_in_server(DEFAULT_SERVER_ID, channel_ids)
            .await
    }

    pub async fn get_local_listeners_for_channels_in_server(
        &self,
        server_id: &str,
        channel_ids: &[u32],
    ) -> Vec<Arc<Box<Client>>> {
        let register = self.register.read().await;
        let mut result = Vec::new();
        for &ch_id in channel_ids {
            let channel_key = ScopedChannelId::new(server_id.to_owned(), ch_id);
            if let Some(ids) = register.listeners_by_channel.get(&channel_key) {
                for id in ids {
                    if let Some(c) = register.local_clients.get(id) {
                        result.push(c.clone());
                    }
                }
            }
        }
        result
    }

    pub(crate) async fn get_local_listener_entries_for_channels_in_server(
        &self,
        server_id: &str,
        channel_ids: &[u32],
    ) -> Vec<(u32, Arc<Box<Client>>)> {
        let register = self.register.read().await;
        let mut result = Vec::new();
        for &channel_id in channel_ids {
            let channel_key = ScopedChannelId::new(server_id.to_owned(), channel_id);
            if let Some(ids) = register.listeners_by_channel.get(&channel_key) {
                for id in ids {
                    if let Some(client) = register.local_clients.get(id) {
                        result.push((channel_id, client.clone()));
                    }
                }
            }
        }
        result
    }

    /// Build a channel/listener interest snapshot for S2S voice node targeting.
    /// Local and replicated remote clients are included by their owning node id.
    pub async fn voice_recipient_index_snapshot(&self) -> RecipientIndexSnapshot {
        let mut snapshot = RecipientIndexSnapshot::new();
        {
            let register = self.register.read().await;
            for (id, client) in &register.local_clients {
                snapshot
                    .entry(RecipientIndexKey::new(
                        id.server_id(),
                        client.get_current_channel_id(),
                    ))
                    .or_default()
                    .insert(id.session_id().get_node_id());
                for listener_channel in client.get_listening_channel_ids() {
                    snapshot
                        .entry(RecipientIndexKey::new(id.server_id(), listener_channel))
                        .or_default()
                        .insert(id.session_id().get_node_id());
                }
            }
        }
        for (_, register) in self.remote_register_snapshots().await {
            for (id, client) in &register.read().await.clients {
                snapshot
                    .entry(RecipientIndexKey::new(
                        id.server_id(),
                        client.get_current_channel_id(),
                    ))
                    .or_default()
                    .insert(id.session_id().get_node_id());
                for listener_channel in client.get_listening_channel_ids() {
                    snapshot
                        .entry(RecipientIndexKey::new(id.server_id(), listener_channel))
                        .or_default()
                        .insert(id.session_id().get_node_id());
                }
            }
        }
        snapshot
    }

    pub async fn len(&self) -> usize {
        let mut len = self.register.read().await.local_clients.len();
        for (_, register) in self.remote_register_snapshots().await {
            len += register.read().await.clients.len();
        }
        len
    }

    pub async fn len_in_server(&self, server_id: &str) -> usize {
        let mut len = self
            .register
            .read()
            .await
            .local_clients()
            .filter(|client| client.server_id() == server_id)
            .count();
        for (_, register) in self.remote_register_snapshots().await {
            len += register
                .read()
                .await
                .clients
                .values()
                .filter(|client| client.server_id() == server_id)
                .count();
        }
        len
    }

    pub async fn local_len(&self) -> usize {
        self.register.read().await.local_clients.len()
    }

    pub async fn local_len_in_server(&self, server_id: &str) -> usize {
        self.register
            .read()
            .await
            .local_clients()
            .filter(|client| client.server_id() == server_id)
            .count()
    }

    /// Return a snapshot of all clients along with the current version
    /// for every known node (local + remote).
    ///
    /// Returns `(clients, versions)` where `versions` maps `node_id -> version`.
    pub async fn snapshot_with_versions(&self) -> (Vec<Arc<Box<Client>>>, HashMap<u16, u64>) {
        let mut clients = Vec::new();
        let mut versions = HashMap::new();
        {
            let register = self.register.read().await;
            clients.extend(register.local_clients().cloned());
            if register.version > 0 {
                versions.insert(self.local_node_id, register.version);
            }
        }
        for (node_id, register) in self.remote_register_snapshots().await {
            let register = register.read().await;
            clients.extend(register.clients.values().cloned());
            if register.version > 0 {
                versions.insert(node_id, register.version);
            }
        }
        (clients, versions)
    }

    pub async fn snapshot_with_versions_in_server(
        &self,
        server_id: &str,
    ) -> (Vec<Arc<Box<Client>>>, HashMap<u16, u64>) {
        let mut clients = Vec::new();
        let mut versions = HashMap::new();
        {
            let register = self.register.read().await;
            clients.extend(
                register
                    .local_clients()
                    .filter(|client| client.server_id() == server_id)
                    .cloned(),
            );
            if register.version > 0 {
                versions.insert(self.local_node_id, register.version);
            }
        }
        for (node_id, register) in self.remote_register_snapshots().await {
            let register = register.read().await;
            clients.extend(
                register
                    .clients
                    .values()
                    .filter(|client| client.server_id() == server_id)
                    .cloned(),
            );
            if register.materialized && register.version > 0 {
                versions.insert(node_id, register.version);
            }
        }
        (clients, versions)
    }

    pub(crate) async fn published_snapshot_with_versions_in_server(
        &self,
        server_id: &str,
    ) -> ClientSnapshotWithVersions {
        let mut clients = Vec::new();
        let mut versions = HashMap::new();
        let mut epochs = HashMap::new();
        {
            let register = self.register.read().await;
            clients.extend(
                register
                    .local_clients()
                    .filter(|client| client.server_id() == server_id)
                    .filter(|client| client.is_published())
                    .cloned(),
            );
            if register.version > 0 {
                versions.insert(self.local_node_id, register.version);
            }
        }
        for (node_id, register) in self.remote_register_snapshots().await {
            let register = register.read().await;
            clients.extend(
                register
                    .clients
                    .values()
                    .filter(|client| client.server_id() == server_id)
                    .cloned(),
            );
            if register.materialized && register.version > 0 {
                versions.insert(node_id, register.version);
            }
            if register.materialized
                && let Some(epoch) = register.epoch
            {
                epochs.insert(node_id, epoch);
            }
        }
        ClientSnapshotWithVersions {
            clients,
            versions,
            epochs,
        }
    }

    #[cfg(test)]
    pub(crate) async fn snapshot_with_versions_and_subscription_in_server(
        &self,
        server_id: &str,
    ) -> (
        Vec<Arc<Box<Client>>>,
        HashMap<u16, u64>,
        ClientStateSubscription,
    ) {
        let rx = self.tx.subscribe();
        let (clients, versions) = self.snapshot_with_versions_in_server(server_id).await;
        (clients, versions, rx)
    }

    pub async fn published_snapshot_with_versions_and_subscription_in_server(
        &self,
        server_id: &str,
    ) -> (
        Vec<Arc<Box<Client>>>,
        HashMap<u16, u64>,
        HashMap<u16, u64>,
        ClientStateSubscription,
    ) {
        let rx = self.tx.subscribe();
        let (clients, versions, epochs) = self
            .published_snapshot_with_versions_in_server(server_id)
            .await
            .into_projection_parts();
        (clients, versions, epochs, rx)
    }

    pub(crate) async fn local_origin_snapshot_entries(&self) -> (u64, Vec<ClientStateLogEntry>) {
        loop {
            self.wait_for_deferred_commits().await;
            // A write guard prevents any operation from committing a version
            // while the matching immutable client states are captured.
            let register = self.register.write().await;
            if self.deferred_commit_pending.load(Ordering::Acquire) > 0 {
                drop(register);
                tokio::task::yield_now().await;
                continue;
            }
            let version = register.version;
            let timestamp = chrono::Utc::now().timestamp_millis();
            let mut entries = register
                .local_clients()
                .filter(|client| client.is_published())
                .map(|client| Self::snapshot_add_entry(self.local_node_id, client, timestamp))
                .collect::<Vec<_>>();
            if self.deferred_commit_pending.load(Ordering::Acquire) > 0 {
                drop(register);
                tokio::task::yield_now().await;
                continue;
            }
            entries.sort_by(Self::compare_snapshot_entries);
            return (version, entries);
        }
    }

    /// Return only repository-materialized epoch/version pairs. Pending
    /// channel-gated operations are deliberately not advertised.
    pub(crate) async fn known_remote_origin_versions(&self) -> HashMap<u16, (u64, u64)> {
        let mut versions = HashMap::new();
        for (node_id, register) in self.remote_register_snapshots().await {
            let register = register.read().await;
            if register.materialized {
                if let Some(epoch) = register.epoch {
                    versions.insert(node_id, (epoch, register.version));
                }
            }
        }
        versions
    }

    /// Canonical materialized snapshot for a remote origin, used only as a
    /// relay fallback. Runtime pending buffers are never included.
    pub(crate) async fn remote_origin_snapshot_entries(
        &self,
        origin: u16,
    ) -> Option<(u64, u64, Vec<ClientStateLogEntry>)> {
        let register = self.get_remote_register(origin).await?;
        let register = register.read().await;
        if !register.materialized {
            return None;
        }
        let epoch = register.epoch?;
        let version = register.version;
        let timestamp = chrono::Utc::now().timestamp_millis();
        let mut entries = register
            .clients
            .values()
            .map(|client| Self::snapshot_add_entry(origin, client, timestamp))
            .collect::<Vec<_>>();
        entries.sort_by(Self::compare_snapshot_entries);
        Some((epoch, version, entries))
    }

    fn compare_snapshot_entries(
        a: &ClientStateLogEntry,
        b: &ClientStateLogEntry,
    ) -> std::cmp::Ordering {
        a.op.server_id().cmp(b.op.server_id()).then_with(|| {
            a.op.session_id()
                .map(u32::from)
                .cmp(&b.op.session_id().map(u32::from))
        })
    }

    fn snapshot_add_entry(origin: u16, client: &Client, timestamp: i64) -> ClientStateLogEntry {
        ClientStateLogEntry {
            version: 0,
            node_id: origin,
            timestamp,
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: client.server_id(),
                session_id: client.get_session_id(),
                client_instance_id: client.client_instance_id(),
                real_ip: client.get_real_ip_address(),
                tcp_addr: client.get_tcp_address(),
                udp_addr: client.get_udp_address(),
                local_addr: client.get_local_address(),
                cert_hash: client
                    .get_certificate_hash()
                    .map(bytes::Bytes::copy_from_slice),
                login_time: client.get_login_time(),
                initial_state: ClientGlobalStateDelta::from_global_state(
                    &client.read_global_state(),
                ),
            },
        }
    }

    pub(crate) async fn install_remote_client_snapshot(
        &self,
        origin: u16,
        epoch: u64,
        envelope_version: u64,
        embedded_version: u64,
        entries: Vec<ClientStateLogEntry>,
        current_channel_versions: &HashMap<String, u64>,
    ) -> Result<ClientSnapshotInstallOutcome, ClientSnapshotInstallError> {
        if origin == self.local_node_id {
            return Err(ClientSnapshotInstallError::new(
                "refusing to install a remote snapshot for the local origin",
            ));
        }
        if envelope_version != embedded_version {
            return Err(ClientSnapshotInstallError::new(format!(
                "client snapshot version mismatch: envelope={envelope_version}, embedded={embedded_version}"
            )));
        }
        if entries.len() as u64 > envelope_version {
            return Err(ClientSnapshotInstallError::new(format!(
                "client snapshot contains {} live entries at version {envelope_version}",
                entries.len()
            )));
        }
        if entries.len() > MAX_CLIENT_ORIGIN_SNAPSHOT_ENTRIES {
            return Err(ClientSnapshotInstallError::new(format!(
                "client snapshot contains {} entries; maximum is {MAX_CLIENT_ORIGIN_SNAPSHOT_ENTRIES}",
                entries.len()
            )));
        }

        let remote_register = self.get_or_create_remote_register(origin).await;
        let mut register = remote_register.write().await;
        match register.epoch {
            Some(current_epoch) if epoch < current_epoch => {
                return Err(ClientSnapshotInstallError::new(format!(
                    "stale client snapshot epoch {epoch}; current epoch is {current_epoch}"
                )));
            }
            Some(current_epoch)
                if epoch == current_epoch
                    && envelope_version < register.version.max(register.epoch_version_floor) =>
            {
                return Err(ClientSnapshotInstallError::new(format!(
                    "regressive client snapshot version {envelope_version}; current floor is {}",
                    register.version.max(register.epoch_version_floor)
                )));
            }
            _ => {}
        }

        let mut scoped_sessions = HashSet::with_capacity(entries.len());
        for entry in &entries {
            if entry.node_id != origin {
                return Err(ClientSnapshotInstallError::new(format!(
                    "client snapshot entry origin {} does not match envelope origin {origin}",
                    entry.node_id
                )));
            }
            let ClientStateOperation::AddClient {
                server_id,
                session_id,
                ..
            } = &entry.op
            else {
                return Err(ClientSnapshotInstallError::new(
                    "client snapshot contains a non-AddClient operation",
                ));
            };
            if session_id.get_node_id() != origin {
                return Err(ClientSnapshotInstallError::new(format!(
                    "client snapshot session {} belongs to another origin",
                    u32::from(*session_id)
                )));
            }
            if !scoped_sessions.insert(ScopedSessionId::new(server_id.clone(), *session_id)) {
                return Err(ClientSnapshotInstallError::new(
                    "client snapshot contains a duplicate scoped session",
                ));
            }
            let available = current_channel_versions
                .get(server_id)
                .copied()
                .unwrap_or(0);
            if entry.channel_version_dep.unwrap_or(0) > available {
                return Ok(ClientSnapshotInstallOutcome::Deferred);
            }
        }
        if register.materialized
            && register.epoch == Some(epoch)
            && envelope_version == register.version
        {
            return Ok(ClientSnapshotInstallOutcome::Installed);
        }

        let first_entry_version = envelope_version - entries.len() as u64 + 1;
        let now = chrono::Utc::now().timestamp_millis();
        let normalized_entries = entries
            .into_iter()
            .enumerate()
            .map(|(index, mut entry)| {
                let version = first_entry_version + index as u64;
                entry.node_id = origin;
                entry.version = version;
                entry.timestamp = now + index as i64;
                Arc::new(entry)
            })
            .collect::<Vec<_>>();

        let retained_pending = if register.epoch == Some(epoch) {
            register
                .pending_ops
                .iter()
                .filter(|(entry, _)| entry.version > envelope_version)
                .cloned()
                .collect::<VecDeque<_>>()
        } else {
            VecDeque::new()
        };

        let mut replacement = RemoteClientRegister::new();
        replacement.epoch = Some(epoch);
        replacement.materialized = true;
        replacement.snapshot_history_floor = envelope_version;
        replacement.epoch_version_floor = envelope_version;
        for entry in &normalized_entries {
            let _ = Self::apply_op_inner(&mut replacement, entry, origin, self.log_max_entries);
        }
        if normalized_entries.is_empty() && envelope_version > 0 {
            let marker = Arc::new(ClientStateLogEntry {
                version: envelope_version,
                node_id: origin,
                timestamp: now,
                channel_version_dep: None,
                op: ClientStateOperation::ResetNode {
                    server_id: crate::types::default_server_id(),
                },
            });
            let _ = Self::apply_op_inner(&mut replacement, &marker, origin, self.log_max_entries);
        }
        replacement.version = envelope_version;
        replacement.pending_ops = retained_pending;
        replacement.pending_channel_versions = register.pending_channel_versions.clone();
        for (server_id, version) in current_channel_versions {
            replacement
                .pending_channel_versions
                .entry(server_id.clone())
                .and_modify(|current| *current = (*current).max(*version))
                .or_insert(*version);
        }
        for (entry, effective_dep) in &replacement.pending_ops {
            replacement
                .last_pending_effective_dep_by_server
                .entry(entry.op.server_id().to_owned())
                .and_modify(|dep| *dep = (*dep).max(*effective_dep))
                .or_insert(*effective_dep);
        }

        let previous_counts = authenticated_counts_by_server(&register.clients);
        let replacement_counts = authenticated_counts_by_server(&replacement.clients);
        *register = replacement;
        self.authenticated_client_counts
            .replace_remote_counts(&previous_counts, &replacement_counts);

        // Snapshot replacement is an atomic state transition, not a sequence
        // from the owner's retained log. Publish a global reset boundary,
        // followed by materialized adds and a final version marker. Connection
        // subscribers use the start boundary to clear this origin from their
        // per-server shadows, including session identities that were reused.
        let reset_versions = HashMap::from([(origin, 0)]);
        let start = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: origin,
            timestamp: now,
            channel_version_dep: None,
            op: ClientStateOperation::ResetNode {
                server_id: crate::types::default_server_id(),
            },
        });
        let _ = self.tx.send(Arc::new(ClientStateBroadcastPayload::new(
            start,
            reset_versions.clone(),
        )));
        for entry in normalized_entries {
            let _ = self.tx.send(Arc::new(ClientStateBroadcastPayload::new(
                entry,
                reset_versions.clone(),
            )));
        }
        if envelope_version > 0 {
            let marker = Arc::new(ClientStateLogEntry {
                version: 1,
                node_id: origin,
                timestamp: now,
                channel_version_dep: None,
                op: ClientStateOperation::ResetNode {
                    server_id: crate::types::default_server_id(),
                },
            });
            let _ = self.tx.send(Arc::new(ClientStateBroadcastPayload::new(
                marker,
                HashMap::from([(origin, envelope_version)]),
            )));
        }

        loop {
            let Some((entry, effective_dep)) = register.pending_ops.front() else {
                break;
            };
            let available_channel_version = register
                .pending_channel_versions
                .get(entry.op.server_id())
                .copied()
                .unwrap_or(0);
            if *effective_dep > available_channel_version || entry.version > register.version + 1 {
                break;
            }
            let (entry, _) = register.pending_ops.pop_front().unwrap();
            if entry.version <= register.version {
                continue;
            }
            let count_change =
                Self::apply_op_inner(&mut register, &entry, origin, self.log_max_entries);
            self.apply_authenticated_client_count_change(count_change);
            let _ = self.tx.send(Arc::new(ClientStateBroadcastPayload::new(
                entry,
                HashMap::from([(origin, register.version)]),
            )));
        }
        register.last_pending_effective_dep_by_server.clear();
        let remaining = register.pending_ops.iter().cloned().collect::<Vec<_>>();
        for (entry, effective_dep) in remaining {
            register
                .last_pending_effective_dep_by_server
                .entry(entry.op.server_id().to_owned())
                .and_modify(|dep| *dep = (*dep).max(effective_dep))
                .or_insert(effective_dep);
        }

        Ok(ClientSnapshotInstallOutcome::Installed)
    }

    /// Replay all log entries newer than the given per-node versions.
    ///
    /// `last_seen` maps `node_id → version` — typically the map returned
    /// by `snapshot_with_versions`.  Returns every `Message` that should
    /// be sent to a client catching up from those versions, along with
    /// the new per-node versions after replay (so the caller can update
    /// the client's `last_client_version` trackers).
    ///
    /// Entries from all nodes are interleaved by timestamp so that the
    /// client sees events in causal order.
    ///
    /// Returns `Err(())` if any log has been pruned past the requested
    /// `last_seen` version, meaning the gap is unrecoverable.
    pub async fn replay_since(
        &self,
        last_seen: &HashMap<u16, u64>,
    ) -> Result<
        (
            Vec<shitspeak_messages::messages::Message>,
            HashMap<u16, u64>,
        ),
        (),
    > {
        self.replay_since_in_server(DEFAULT_SERVER_ID, last_seen)
            .await
    }

    pub async fn replay_since_in_server(
        &self,
        server_id: &str,
        last_seen: &HashMap<u16, u64>,
    ) -> Result<
        (
            Vec<shitspeak_messages::messages::Message>,
            HashMap<u16, u64>,
        ),
        (),
    > {
        self.replay_since_in_server_filtered(server_id, last_seen, None)
            .await
    }

    pub async fn replay_since_in_server_for_client(
        &self,
        server_id: &str,
        last_seen: &HashMap<u16, u64>,
        viewer_session_id: ClientSessionIdentifier,
        viewer_client_instance_id: ClientInstanceId,
    ) -> Result<
        (
            Vec<shitspeak_messages::messages::Message>,
            HashMap<u16, u64>,
        ),
        (),
    > {
        self.replay_since_in_server_filtered(
            server_id,
            last_seen,
            Some((viewer_session_id, viewer_client_instance_id)),
        )
        .await
    }

    pub async fn replay_entries_since_in_server_for_client(
        &self,
        server_id: &str,
        last_seen: &HashMap<u16, u64>,
        last_epochs: &HashMap<u16, u64>,
        viewer_session_id: ClientSessionIdentifier,
        viewer_client_instance_id: ClientInstanceId,
    ) -> ClientProjectionCatchUp {
        self.client_projection_catch_up(
            server_id,
            last_seen,
            Some(last_epochs),
            Some((viewer_session_id, viewer_client_instance_id)),
        )
        .await
    }

    async fn replay_since_in_server_filtered(
        &self,
        server_id: &str,
        last_seen: &HashMap<u16, u64>,
        viewer: Option<(ClientSessionIdentifier, ClientInstanceId)>,
    ) -> Result<
        (
            Vec<shitspeak_messages::messages::Message>,
            HashMap<u16, u64>,
        ),
        (),
    > {
        let plan = self
            .client_projection_catch_up(server_id, last_seen, None, None)
            .await;
        let (rebases, entries, target_versions, _) = plan.into_parts();
        if !rebases.is_empty() {
            tracing::error!(
                origins = ?rebases.iter().map(ClientOriginRebase::origin).collect::<Vec<_>>(),
                "Client log replay requires a materialized rebase"
            );
            return Err(());
        }

        // Convert to messages
        let mut messages = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some((viewer_session_id, viewer_client_instance_id)) = viewer {
                messages.extend(
                    entry
                        .messages_for_client(self, viewer_session_id, viewer_client_instance_id)
                        .await,
                );
            } else if let Some(msg) = entry.to_message(self).await {
                messages.push(msg);
            }
        }

        Ok((messages, target_versions))
    }

    async fn client_projection_catch_up(
        &self,
        server_id: &str,
        last_seen: &HashMap<u16, u64>,
        last_epochs: Option<&HashMap<u16, u64>>,
        viewer: Option<(ClientSessionIdentifier, ClientInstanceId)>,
    ) -> ClientProjectionCatchUp {
        let local_since = last_seen.get(&self.local_node_id).copied().unwrap_or(0);
        let mut entries: Vec<Arc<ClientStateLogEntry>> = Vec::new();
        let mut rebases = Vec::new();
        let mut target_versions = HashMap::new();
        let mut target_epochs = HashMap::new();
        loop {
            self.wait_for_deferred_commits().await;
            // Local client state is mutated before its matching log commit.
            // Fence deferred commits and hold the write guard while capturing
            // a materialized rebase so state and target_version are one cut.
            let register = self.register.write().await;
            if self.deferred_commit_pending.load(Ordering::Acquire) > 0 {
                drop(register);
                tokio::task::yield_now().await;
                continue;
            }

            let target_version = register.version;
            if local_since > target_version
                || !Self::log_has_contiguous_suffix(
                    &register.local_log,
                    local_since,
                    target_version,
                )
            {
                let timestamp = chrono::Utc::now().timestamp_millis();
                let mut snapshot_entries = register
                    .local_clients()
                    .filter(|client| client.server_id() == server_id)
                    .filter(|client| client.is_published())
                    .map(|client| {
                        Self::projection_snapshot_entry(
                            self.local_node_id,
                            target_version,
                            client,
                            timestamp,
                        )
                    })
                    .collect::<Vec<_>>();
                if let Some((viewer_session_id, viewer_client_instance_id)) = viewer {
                    let scoped_id = ScopedSessionId::new(server_id.to_owned(), viewer_session_id);
                    if let Some(client) = register.local_clients.get(&scoped_id)
                        && client.client_instance_id() == viewer_client_instance_id
                        && !client.is_published()
                    {
                        snapshot_entries.push(Self::projection_snapshot_entry(
                            self.local_node_id,
                            target_version,
                            client,
                            timestamp,
                        ));
                    }
                }
                if self.deferred_commit_pending.load(Ordering::Acquire) > 0 {
                    drop(register);
                    tokio::task::yield_now().await;
                    continue;
                }
                snapshot_entries.sort_by(|a, b| Self::compare_snapshot_entries(a, b));
                rebases.push(ClientOriginRebase {
                    origin: self.local_node_id,
                    version: target_version,
                    epoch: None,
                    entries: snapshot_entries.into_iter().map(Arc::new).collect(),
                });
            } else {
                for entry in &register.local_log {
                    if entry.version > local_since && entry.op.server_id() == server_id {
                        entries.push(Arc::clone(entry));
                    }
                }
            }
            target_versions.insert(self.local_node_id, target_version);
            break;
        }

        for (node_id, remote_register) in self.remote_register_snapshots().await {
            let since = last_seen.get(&node_id).copied().unwrap_or(0);
            let register = remote_register.read().await;
            let target_version = register.version;
            let target_epoch = register.epoch;
            target_versions.insert(node_id, target_version);
            if let Some(epoch) = target_epoch {
                target_epochs.insert(node_id, epoch);
            }
            let epoch_mismatch = last_epochs.is_some_and(|epochs| {
                let previous_epoch = epochs.get(&node_id).copied();
                let had_cursor = last_seen.contains_key(&node_id) || previous_epoch.is_some();
                had_cursor && previous_epoch != target_epoch
            });
            if epoch_mismatch
                || since < register.snapshot_history_floor
                || since > target_version
                || !Self::log_has_contiguous_suffix(&register.log, since, target_version)
            {
                let timestamp = chrono::Utc::now().timestamp_millis();
                let mut snapshot_entries = register
                    .clients
                    .values()
                    .filter(|client| client.server_id() == server_id)
                    .map(|client| {
                        Self::projection_snapshot_entry(node_id, target_version, client, timestamp)
                    })
                    .collect::<Vec<_>>();
                snapshot_entries.sort_by(|a, b| Self::compare_snapshot_entries(a, b));
                rebases.push(ClientOriginRebase {
                    origin: node_id,
                    version: target_version,
                    epoch: target_epoch,
                    entries: snapshot_entries.into_iter().map(Arc::new).collect(),
                });
            } else {
                for entry in &register.log {
                    if entry.version > since && entry.op.server_id() == server_id {
                        entries.push(Arc::clone(entry));
                    }
                }
            }
        }

        if let Some((viewer_session_id, viewer_client_instance_id)) = viewer {
            entries.retain(|entry| {
                !is_own_replayed_add_client(&entry.op, viewer_session_id, viewer_client_instance_id)
            });
            for rebase in &mut rebases {
                for entry in &mut rebase.entries {
                    authoritative_rebase_entry_for_viewer(
                        Arc::make_mut(entry),
                        viewer_session_id,
                        viewer_client_instance_id,
                    );
                }
            }
        }

        // Sort by timestamp, then version for deterministic ordering
        entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.node_id.cmp(&b.node_id))
                .then_with(|| a.version.cmp(&b.version))
        });
        rebases.sort_by_key(ClientOriginRebase::origin);

        ClientProjectionCatchUp {
            rebases,
            entries,
            target_versions,
            target_epochs,
        }
    }

    fn log_has_contiguous_suffix(
        log: &VecDeque<Arc<ClientStateLogEntry>>,
        since: u64,
        current: u64,
    ) -> bool {
        if since >= current {
            return since == current;
        }

        let mut expected = since + 1;
        for entry in log.iter().filter(|entry| entry.version > since) {
            if entry.version != expected {
                return false;
            }
            expected += 1;
        }
        expected == current + 1
    }

    fn projection_snapshot_entry(
        origin: u16,
        version: u64,
        client: &Client,
        timestamp: i64,
    ) -> ClientStateLogEntry {
        let mut entry = Self::snapshot_add_entry(origin, client, timestamp);
        entry.version = version;
        entry
    }

    /// Send `message` to a single client identified by `id`.
    /// Returns `true` if the client was found and the write succeeded.
    pub async fn send_to(
        &self,
        id: ClientSessionIdentifier,
        message: &shitspeak_messages::messages::Message,
    ) -> bool {
        self.send_to_in_server(DEFAULT_SERVER_ID, id, message).await
    }

    pub async fn send_to_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
        message: &shitspeak_messages::messages::Message,
    ) -> bool {
        let client = self.get_client_in_server(server_id, id).await;
        match client {
            Some(c) => {
                if let Err(e) = c.write_proto_message(message).await {
                    c.in_tracing_scope(|| tracing::warn!("send_to {id:?} write error: {e}"));
                    false
                } else {
                    true
                }
            }
            None => false,
        }
    }

    // ── Versioned state log ─────────────────────────────────────────────

    /// Return the current local version.
    pub fn current_version(&self) -> u64 {
        self.versions.current()
    }

    pub(crate) fn recommended_projection_event_capacity(&self) -> usize {
        projection_broadcast_capacity(self.log_max_entries)
    }

    pub fn current_version_in_server(&self, server_id: &str) -> u64 {
        self.versions.current_in_server(server_id)
    }

    pub(crate) fn voice_routing_generation_in_server(&self, server_id: &str) -> u64 {
        self.versions.voice_routing_in_server(server_id)
    }

    /// Subscribe to the stream of committed `ClientStateLogEntry`s.
    /// Used by per-client TCP loops and future S2S replication.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<ClientStateBroadcastPayload>> {
        self.tx.subscribe()
    }

    /// Return all local log entries with `version > since_version`.
    pub async fn get_log_since(&self, since_version: u64) -> Vec<Arc<ClientStateLogEntry>> {
        self.get_log_since_for_node(self.local_node_id, since_version)
            .await
    }

    pub(crate) async fn get_log_since_for_node(
        &self,
        node_id: u16,
        since_version: u64,
    ) -> Vec<Arc<ClientStateLogEntry>> {
        if node_id == self.local_node_id {
            return self
                .register
                .read()
                .await
                .local_log
                .iter()
                .filter(|op| op.version > since_version)
                .cloned()
                .collect();
        }

        let Some(register) = self.get_remote_register(node_id).await else {
            return Vec::new();
        };
        register
            .read()
            .await
            .log
            .iter()
            .filter(|op| op.version > since_version)
            .cloned()
            .collect()
    }

    pub(crate) async fn get_log_slice_for_node(
        &self,
        node_id: u16,
        since_version: u64,
    ) -> ClientOriginLogSlice {
        if node_id == self.local_node_id {
            let register = self.register.read().await;
            return Self::continuous_log_slice(
                &register.local_log,
                register.version,
                0,
                since_version,
            );
        }

        let Some(register) = self.get_remote_register(node_id).await else {
            return ClientOriginLogSlice::TooOld;
        };
        let register = register.read().await;
        if !register.materialized {
            return ClientOriginLogSlice::TooOld;
        }
        Self::continuous_log_slice(
            &register.log,
            register.version,
            register.snapshot_history_floor,
            since_version,
        )
    }

    fn continuous_log_slice(
        log: &VecDeque<Arc<ClientStateLogEntry>>,
        current_version: u64,
        snapshot_history_floor: u64,
        since_version: u64,
    ) -> ClientOriginLogSlice {
        if since_version < snapshot_history_floor || since_version > current_version {
            return ClientOriginLogSlice::TooOld;
        }
        if since_version == current_version {
            return ClientOriginLogSlice::Available(Vec::new());
        }
        let expected = since_version + 1;
        let Some(first) = log.iter().find(|entry| entry.version > since_version) else {
            return ClientOriginLogSlice::TooOld;
        };
        if first.version != expected {
            return ClientOriginLogSlice::TooOld;
        }
        ClientOriginLogSlice::Available(
            log.iter()
                .filter(|entry| entry.version > since_version)
                .cloned()
                .collect(),
        )
    }

    /// Apply an operation that arrived from a remote node.
    ///
    /// The operation is applied to the local in-memory map but **not**
    /// re-appended to the local log or re-sent over S2S (the remote node
    /// already did that). It is broadcast to local client subscribers so they
    /// observe replicated remote user state. Idempotent: if
    /// `op.version <= current_version` for that remote node, the op is dropped.
    ///
    /// `current_channel_version` is the local channel repository's current
    /// version for `op.op.server_id()`. If the op has a `channel_version_dep`
    /// that exceeds this, it is buffered until that server scope catches up.
    pub async fn apply_remote_operation(
        &self,
        op: Arc<ClientStateLogEntry>,
        current_channel_version: u64,
    ) -> Result<(), ()> {
        self.apply_remote_operation_with_epoch(0, op, current_channel_version)
            .await
    }

    /// Epoch-fenced remote application used by owner replication.
    pub(crate) async fn apply_remote_operation_with_epoch(
        &self,
        origin_epoch: u64,
        op: Arc<ClientStateLogEntry>,
        current_channel_version: u64,
    ) -> Result<(), ()> {
        let remote_node = op.node_id;
        if remote_node == self.local_node_id {
            return Ok(());
        }
        let remote_register = self.get_or_create_remote_register(remote_node).await;
        {
            let mut register = remote_register.write().await;
            match register.epoch {
                Some(current_epoch) if origin_epoch < current_epoch => {
                    tracing::warn!(
                        remote_node,
                        origin_epoch,
                        current_epoch,
                        "rejecting stale-epoch remote client operation"
                    );
                    return Err(());
                }
                Some(current_epoch) if origin_epoch > current_epoch => {
                    let previous_counts = authenticated_counts_by_server(&register.clients);
                    let removals = register
                        .clients
                        .iter()
                        .map(|(id, client)| {
                            (
                                id.clone(),
                                client.is_published(),
                                client.client_instance_id(),
                            )
                        })
                        .collect();
                    let base_version = register.version;
                    register.clear_materialized_state();
                    self.authenticated_client_counts
                        .replace_remote_counts(&previous_counts, &HashMap::new());
                    register.epoch = Some(origin_epoch);
                    register.epoch_version_floor = 0;
                    register.materialized = true;
                    self.broadcast_origin_removals(remote_node, removals, base_version);
                }
                None => {
                    register.epoch = Some(origin_epoch);
                    register.materialized = true;
                }
                Some(_) if !register.materialized => {
                    tracing::warn!(
                        remote_node,
                        origin_epoch,
                        version = op.version,
                        "rejecting remote client operation while same-epoch origin is inactive; snapshot required"
                    );
                    return Err(());
                }
                Some(_) => {
                    register.materialized = true;
                }
            }
            let server_id = op.op.server_id().to_owned();

            // Check version against the remote node's tracked version and pending window.
            let current_ver = register.version;
            if op.version <= current_ver
                || register
                    .pending_ops
                    .iter()
                    .any(|(pending, _)| pending.version == op.version)
            {
                return Ok(());
            }
            let expected_next_version = current_ver + 1;
            let has_earlier_pending = register
                .pending_ops
                .iter()
                .any(|(pending, _)| pending.version < op.version);

            register
                .pending_channel_versions
                .entry(server_id.clone())
                .and_modify(|version| *version = (*version).max(current_channel_version))
                .or_insert(current_channel_version);

            let previous_effective_dep = register
                .last_pending_effective_dep_by_server
                .get(&server_id)
                .copied()
                .unwrap_or(0);
            let own_dep = op.channel_version_dep.unwrap_or(0);
            let effective_dep = own_dep.max(previous_effective_dep);

            if has_earlier_pending
                || op.version > expected_next_version
                || effective_dep > current_channel_version
            {
                tracing::debug!(
                    server_id = %server_id,
                    waiting_for_pending = has_earlier_pending,
                    expected_next_version,
                    "Buffering remote client op v{} (node {}) — waiting for version {} / channel v{} (have v{})",
                    op.version,
                    remote_node,
                    expected_next_version,
                    effective_dep,
                    current_channel_version,
                );
                register
                    .last_pending_effective_dep_by_server
                    .insert(server_id, effective_dep);
                let insert_at = register
                    .pending_ops
                    .iter()
                    .position(|(pending, _)| pending.version > op.version)
                    .unwrap_or(register.pending_ops.len());
                register.pending_ops.insert(insert_at, (op, effective_dep));
                return Ok(());
            }

            if op.version < expected_next_version {
                return Ok(());
            }
            let count_change =
                Self::apply_op_inner(&mut register, &op, remote_node, self.log_max_entries);
            self.apply_authenticated_client_count_change(count_change);
            let _ = self.tx.send(Arc::new(ClientStateBroadcastPayload::new(
                Arc::clone(&op),
                HashMap::from([(remote_node, register.version)]),
            )));
        }
        Ok(())
    }

    /// Drain pending remote ops for `server_id` whose effective dependency is <= `channel_version`.
    /// Called after channel state in that server scope is advanced.
    pub async fn drain_pending_ops(&self, server_id: &str, channel_version: u64) {
        for (remote_node, remote_register) in self.remote_register_snapshots().await {
            let mut register = remote_register.write().await;
            register
                .pending_channel_versions
                .entry(server_id.to_owned())
                .and_modify(|version| *version = (*version).max(channel_version))
                .or_insert(channel_version);

            loop {
                let Some((op, effective_dep)) = register.pending_ops.front() else {
                    break;
                };
                let op_server_id = op.op.server_id().to_owned();
                let available_channel_version = register
                    .pending_channel_versions
                    .get(&op_server_id)
                    .copied()
                    .unwrap_or(0);
                if *effective_dep > available_channel_version {
                    break;
                }

                let expected_next_version = register.version + 1;
                if op.version > expected_next_version {
                    break;
                }

                let (op, _) = register.pending_ops.pop_front().unwrap();
                if op.version < expected_next_version {
                    continue;
                }
                tracing::debug!(
                    server_id = %op_server_id,
                    "Draining buffered remote client op v{} (node {}) at channel v{}",
                    op.version,
                    remote_node,
                    available_channel_version,
                );
                let count_change =
                    Self::apply_op_inner(&mut register, &op, remote_node, self.log_max_entries);
                self.apply_authenticated_client_count_change(count_change);
                let _ = self.tx.send(Arc::new(ClientStateBroadcastPayload::new(
                    Arc::clone(&op),
                    HashMap::from([(remote_node, register.version)]),
                )));
            }

            register.last_pending_effective_dep_by_server.clear();
            let pending: Vec<(String, u64)> = register
                .pending_ops
                .iter()
                .map(|(op, effective_dep)| (op.op.server_id().to_owned(), *effective_dep))
                .collect();
            for (pending_server_id, effective_dep) in pending {
                register
                    .last_pending_effective_dep_by_server
                    .entry(pending_server_id)
                    .and_modify(|dep| *dep = (*dep).max(effective_dep))
                    .or_insert(effective_dep);
            }
        }
    }

    /// Apply a single remote op to the register (no version/buffer checks).
    fn apply_op_inner(
        register: &mut RemoteClientRegister,
        op: &ClientStateLogEntry,
        remote_node: u16,
        log_max_entries: usize,
    ) -> Option<AuthenticatedClientCountChange> {
        let count_change = match &op.op {
            ClientStateOperation::AddClient {
                server_id,
                session_id,
                client_instance_id,
                real_ip,
                tcp_addr,
                udp_addr,
                local_addr,
                cert_hash,
                login_time,
                initial_state,
            } => {
                tracing::debug!("remote AddClient {session_id:?} v{}", op.version);
                if session_id.get_node_id() != remote_node {
                    tracing::warn!(
                        remote_node,
                        session = u32::from(*session_id),
                        "remote AddClient ignored: session node does not match operation origin"
                    );
                    None
                } else {
                    let scoped_id = ScopedSessionId::new(server_id.clone(), *session_id);
                    let client = Arc::new(Client::new_remote_in_server(
                        server_id.clone(),
                        *session_id,
                        *real_ip,
                        *tcp_addr,
                        *udp_addr,
                        *local_addr,
                        cert_hash.clone(),
                        *login_time,
                        *client_instance_id,
                    ));
                    {
                        let mut gs = client.write_global_state_direct();
                        apply_delta_to_global_state(&mut gs, initial_state);
                        client.set_can_receive_voice(gs.can_receive_voice());
                    }
                    client.record_tracing_span_identity();
                    let channel_id = client.get_current_channel_id();
                    let listener_channels = client.get_listening_channel_ids();
                    let added = register.clients.insert(scoped_id.clone(), client).is_none();
                    register.channel_index_insert(scoped_id.clone(), channel_id);
                    for channel_id in listener_channels {
                        register.listener_index_add(scoped_id.clone(), channel_id);
                    }
                    added.then(|| AuthenticatedClientCountChange::Added(server_id.clone()))
                }
            }
            ClientStateOperation::RemoveClient {
                server_id,
                session_id,
                client_instance_id,
                ..
            } => {
                // Remote clients are not in the channel/listener index, so
                // no index cleanup is necessary here.
                let scoped_id = ScopedSessionId::new(server_id.clone(), *session_id);
                let should_remove = register
                    .clients
                    .get(&scoped_id)
                    .map(|client| {
                        *client_instance_id == 0
                            || client.client_instance_id() == *client_instance_id
                    })
                    .unwrap_or(false);
                if should_remove {
                    register.clients.remove(&scoped_id);
                    register.channel_index_remove(&scoped_id);
                    register.listener_index_remove_all(&scoped_id);
                    Some(AuthenticatedClientCountChange::Removed(server_id.clone()))
                } else {
                    tracing::trace!(
                        remote_node,
                        session = u32::from(*session_id),
                        client_instance_id,
                        "remote RemoveClient ignored: client instance mismatch"
                    );
                    None
                }
            }
            ClientStateOperation::UpdateGlobalState {
                server_id,
                session_id,
                client_instance_id,
                sender_session_id: _,
                delta,
            } => {
                let scoped_id = ScopedSessionId::new(server_id.clone(), *session_id);
                let client = register.clients.get(&scoped_id).cloned();
                if let Some(client) = client {
                    if *client_instance_id == 0
                        || client.client_instance_id() == *client_instance_id
                    {
                        if let Some(new_ch) = delta.current_channel_id {
                            register.channel_index_move(scoped_id.clone(), new_ch);
                        }
                        if let Some(ref adds) = delta.listening_channel_add {
                            for &ch in adds {
                                register.listener_index_add(scoped_id.clone(), ch);
                            }
                        }
                        if let Some(ref removes) = delta.listening_channel_remove {
                            for &ch in removes {
                                register.listener_index_remove_channel(&scoped_id, ch);
                            }
                        }
                        {
                            let mut gs = client.write_global_state_direct();
                            apply_delta_to_global_state(&mut gs, delta);
                            client.set_can_receive_voice(gs.can_receive_voice());
                        }
                        client.record_tracing_span_identity();
                    } else {
                        tracing::trace!(
                            remote_node,
                            session = u32::from(*session_id),
                            client_instance_id,
                            "remote UpdateGlobalState ignored: client instance mismatch"
                        );
                    }
                }
                None
            }
            ClientStateOperation::ResetNode { .. } => None,
        };

        register.log.push_back(Arc::new(op.clone()));
        while register.log.len() > log_max_entries {
            register.log.pop_front();
        }
        register.version = op.version;
        register.epoch_version_floor = register.epoch_version_floor.max(op.version);
        count_change
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Create a new log entry and commit it: bump version, push to ring
    /// buffer, broadcast to subscribers, trim old entries.
    ///
    /// Acquires the register write lock internally.
    pub(crate) async fn commit_operation(
        &self,
        op: ClientStateOperation,
        channel_version_dep: Option<u64>,
    ) -> Option<Arc<ClientStateBroadcastPayload>> {
        self.wait_for_deferred_commits().await;
        let broadcast = {
            let mut register = self.register.write().await;
            Self::commit_operation_inner(
                &mut register,
                self.local_node_id,
                self.log_max_entries,
                &self.versions,
                op,
                channel_version_dep,
            )
        };
        if let Some(broadcast) = broadcast {
            let _ = self.tx.send(Arc::clone(&broadcast));
            Some(broadcast)
        } else {
            None
        }
    }

    async fn wait_for_deferred_commits(&self) {
        while self.deferred_commit_pending.load(Ordering::Acquire) > 0 {
            tokio::task::yield_now().await;
        }
    }

    /// Synchronous version of `commit_operation`.  Safe to call from
    /// `Drop` impls (uses `try_write`).
    pub(crate) fn commit_operation_sync(
        &self,
        op: ClientStateOperation,
        channel_version_dep: Option<u64>,
    ) {
        let mut commit = DeferredClientCommit {
            op,
            channel_version_dep,
        };
        if self.deferred_commit_pending.load(Ordering::Acquire) > 0 {
            match self.enqueue_deferred_commit(commit) {
                Ok(()) => return,
                Err(returned) => commit = returned,
            }
        }

        match self.register.try_write() {
            Ok(mut register) => {
                let Some(broadcast) = Self::commit_operation_inner(
                    &mut register,
                    self.local_node_id,
                    self.log_max_entries,
                    &self.versions,
                    commit.op,
                    commit.channel_version_dep,
                ) else {
                    return;
                };
                // Broadcast to subscribers (ignore NoSubscribers / Full errors)
                let _ = self.tx.send(broadcast);
            }
            Err(_) => {
                if self.enqueue_deferred_commit(commit).is_ok() {
                    return;
                }
                tracing::warn!("client state commit dropped: repository lock contended");
            }
        }
    }

    fn enqueue_deferred_commit(
        &self,
        commit: DeferredClientCommit,
    ) -> Result<(), DeferredClientCommit> {
        let Some(tx) = self.deferred_commit_tx.as_ref() else {
            return Err(commit);
        };
        self.deferred_commit_pending.fetch_add(1, Ordering::AcqRel);
        match tx.send(commit) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.deferred_commit_pending.fetch_sub(1, Ordering::AcqRel);
                Err(error.0)
            }
        }
    }

    fn commit_operation_inner(
        register: &mut ClientRegister,
        local_node_id: u16,
        log_max_entries: usize,
        versions: &ClientVersionIndex,
        op: ClientStateOperation,
        channel_version_dep: Option<u64>,
    ) -> Option<Arc<ClientStateBroadcastPayload>> {
        // A client Arc can outlive its repository entry while an async handler
        // is pending. Reject its eventual state commit atomically under the
        // repository lock so a reused session cannot receive stale indices or
        // broadcasts from the previous connection.
        if let ClientStateOperation::UpdateGlobalState {
            server_id,
            session_id,
            client_instance_id,
            ..
        } = &op
        {
            let scoped_id = ScopedSessionId::new(server_id.clone(), *session_id);
            let is_current_instance = register
                .local_clients
                .get(&scoped_id)
                .is_some_and(|client| client.client_instance_id() == *client_instance_id);
            if !is_current_instance {
                return None;
            }
        }

        // Update channel/listener indices for any state change, before the
        // early-return for unpublished clients (the index is local state,
        // not propagated over the log).
        if let ClientStateOperation::UpdateGlobalState {
            server_id,
            session_id,
            delta,
            ..
        } = &op
        {
            let scoped_id = ScopedSessionId::new(server_id.clone(), *session_id);
            if let Some(new_ch) = delta.current_channel_id {
                register.channel_index_move(scoped_id.clone(), new_ch);
            }
            if let Some(ref adds) = delta.listening_channel_add {
                for &ch in adds {
                    register.listener_index_add(scoped_id.clone(), ch);
                }
            }
            if let Some(ref removes) = delta.listening_channel_remove {
                for &ch in removes {
                    register.listener_index_remove_channel(&scoped_id, ch);
                }
            }
        }

        // Suppress log entries and broadcasts for UpdateGlobalState on
        // unpublished clients.  The in-memory write has already happened;
        // the subsequent AddClient (from publish_client) will snapshot the
        // full current state.  This prevents unauthenticated clients from
        // appearing to other users before auth completes.
        if let ClientStateOperation::UpdateGlobalState {
            server_id,
            session_id,
            ..
        } = &op
        {
            let scoped_id = ScopedSessionId::new(server_id.clone(), *session_id);
            let is_published = register
                .local_clients
                .get(&scoped_id)
                .map(|c| c.is_published())
                .unwrap_or(false);
            if !is_published {
                return None;
            }
        }

        register.version += 1;
        let version = register.version;
        debug_assert!(
            version < u64::MAX - 1_000_000,
            "ClientRepository version counter approaching u64::MAX - likely a bug"
        );
        versions.record(&op, version);

        let entry = Arc::new(ClientStateLogEntry {
            version,
            node_id: local_node_id,
            timestamp: chrono::Utc::now().timestamp_millis(),
            channel_version_dep,
            op,
        });

        register.local_log.push_back(Arc::clone(&entry));
        while register.local_log.len() > log_max_entries {
            register.local_log.pop_front();
        }

        let versions = HashMap::from([(local_node_id, version)]);
        Some(Arc::new(ClientStateBroadcastPayload::new(entry, versions)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use chrono::Utc;
    use shitspeak_messages::messages::{Message, encoder::TextMessage};

    use super::*;

    #[test]
    fn replicated_delta_applies_and_clears_fqdn() {
        let mut state = crate::client::client_global_state::ClientGlobalState::new();

        apply_delta_to_global_state(
            &mut state,
            &ClientGlobalStateDelta {
                fqdn: Some(Some("alice.auth.example".to_owned())),
                ..Default::default()
            },
        );
        assert_eq!(state.get_fqdn(), Some("alice.auth.example"));

        apply_delta_to_global_state(
            &mut state,
            &ClientGlobalStateDelta {
                fqdn: Some(None),
                ..Default::default()
            },
        );
        assert_eq!(state.get_fqdn(), None);
    }

    #[test]
    fn projection_broadcast_capacity_tracks_retention_with_a_safe_minimum() {
        assert_eq!(projection_broadcast_capacity(1), 1024);
        assert_eq!(projection_broadcast_capacity(511), 1024);
        assert_eq!(projection_broadcast_capacity(512), 1024);
        assert_eq!(projection_broadcast_capacity(513), 1026);
        assert_eq!(projection_broadcast_capacity(2000), 4000);
    }

    #[test]
    fn version_index_separates_log_and_voice_generations() {
        let versions = ClientVersionIndex::default();
        let session_id = ClientSessionIdentifier::new(1, 7).unwrap();
        let irrelevant = ClientStateOperation::UpdateGlobalState {
            server_id: "alpha".to_owned(),
            session_id,
            client_instance_id: 1,
            sender_session_id: None,
            delta: ClientGlobalStateDelta {
                comment_hash: Some(Some("hash".to_owned())),
                ..Default::default()
            },
        };
        let relevant = ClientStateOperation::UpdateGlobalState {
            server_id: "alpha".to_owned(),
            session_id,
            client_instance_id: 1,
            sender_session_id: None,
            delta: ClientGlobalStateDelta {
                deaf: Some(true),
                ..Default::default()
            },
        };

        versions.record(
            &ClientStateOperation::ResetNode {
                server_id: "alpha".to_owned(),
            },
            1,
        );
        versions.record(&irrelevant, 2);
        assert_eq!(versions.current(), 2);
        assert_eq!(versions.current_in_server("alpha"), 2);
        assert_eq!(versions.voice_routing_in_server("alpha"), 1);

        versions.record(&relevant, 3);
        assert_eq!(versions.current_in_server("alpha"), 3);
        assert_eq!(versions.voice_routing_in_server("alpha"), 3);
    }

    #[tokio::test]
    async fn authenticated_client_reservations_are_atomic_scoped_and_released() {
        let repo = ClientRepository::new(1, 128);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (first_tx, _first_rx) = tokio::sync::mpsc::channel(8);
        let first = repo
            .allocate_web_client_in_server(
                "alpha",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001),
                local,
                first_tx,
            )
            .await;
        let (second_tx, _second_rx) = tokio::sync::mpsc::channel(8);
        let second = repo
            .allocate_web_client_in_server(
                "alpha",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30002),
                local,
                second_tx,
            )
            .await;

        let (first_reserved, second_reserved) = tokio::join!(
            repo.try_reserve_authenticated_client_in_server("alpha", first.get_session_id(), 1),
            repo.try_reserve_authenticated_client_in_server("alpha", second.get_session_id(), 1),
        );
        assert_ne!(first_reserved, second_reserved);
        assert_eq!(repo.authenticated_client_count_in_server("alpha"), 1);

        let (winner, loser) = if first_reserved {
            (&first, &second)
        } else {
            (&second, &first)
        };
        repo.remove_client_in_server("alpha", winner.get_session_id())
            .await;
        assert_eq!(repo.authenticated_client_count_in_server("alpha"), 0);
        assert!(
            repo.try_reserve_authenticated_client_in_server("alpha", loser.get_session_id(), 1)
                .await
        );
        repo.release_authenticated_client_reservation_in_server("alpha", loser.get_session_id())
            .await;
        assert_eq!(repo.authenticated_client_count_in_server("alpha"), 0);
        assert!(
            repo.try_reserve_authenticated_client_in_server("alpha", loser.get_session_id(), 1)
                .await
        );

        let moved_session = repo
            .move_local_client_to_server("alpha", loser.get_session_id(), "beta")
            .await
            .expect("reserved client moves between server scopes");
        assert_eq!(repo.authenticated_client_count_in_server("alpha"), 0);
        assert_eq!(repo.authenticated_client_count_in_server("beta"), 1);
        repo.remove_client_in_server("beta", moved_session).await;
        assert_eq!(repo.authenticated_client_count_in_server("beta"), 0);
    }

    #[tokio::test]
    async fn publishing_an_authenticated_client_adopts_one_counted_slot() {
        let repo = ClientRepository::new(1, 128);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30003);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;

        client.set_authenticated(true);
        repo.publish_client_in_server("alpha", client.get_session_id())
            .await;
        repo.publish_client_in_server("alpha", client.get_session_id())
            .await;
        assert_eq!(repo.authenticated_client_count_in_server("alpha"), 1);

        repo.remove_client_in_server("alpha", client.get_session_id())
            .await;
        assert_eq!(repo.authenticated_client_count_in_server("alpha"), 0);
    }

    fn text_message(message: &str) -> Message {
        Message::TextMessage(
            TextMessage {
                actor: Some(12),
                session: Vec::new(),
                channel_id: Vec::new(),
                tree_id: Vec::new(),
                message: message.to_string(),
            }
            .into(),
        )
    }

    async fn assert_register_read_completes_while_write_is_queued(
        repo: &Arc<ClientRepository>,
        expected_local_count: usize,
    ) {
        let writer = tokio::spawn({
            let repo = Arc::clone(repo);
            async move {
                let _guard = repo.register.write().await;
            }
        });
        tokio::task::yield_now().await;

        let count =
            tokio::time::timeout(Duration::from_millis(50), repo.local_len_in_server("alpha"))
                .await
                .expect("repository readers should not be blocked by unrelated async work");
        assert_eq!(count, expected_local_count);

        writer.abort();
        let _ = writer.await;
    }

    async fn remote_add_entry(
        node_id: u16,
        local_session_id: u32,
        version: u64,
    ) -> Arc<ClientStateLogEntry> {
        remote_add_entry_in_server("alpha", node_id, local_session_id, version).await
    }

    async fn remote_add_entry_in_server(
        server_id: &str,
        node_id: u16,
        local_session_id: u32,
        version: u64,
    ) -> Arc<ClientStateLogEntry> {
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001 + u16::try_from(local_session_id).unwrap());
        let local_addr = SocketAddr::new(real_ip, 64738);
        let session_id = ClientSessionIdentifier::new(node_id, local_session_id).unwrap();
        Arc::new(ClientStateLogEntry {
            version,
            node_id,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: server_id.to_owned(),
                session_id,
                client_instance_id: u64::from(node_id) << 32 | u64::from(local_session_id),
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        })
    }

    async fn commit_alpha_add_client(
        repo: &ClientRepository,
        session: ClientSessionIdentifier,
        client_instance_id: ClientInstanceId,
    ) {
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);

        repo.commit_operation(
            ClientStateOperation::AddClient {
                server_id: "alpha".to_string(),
                session_id: session,
                client_instance_id,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn web_client_allocation_produces_local_writable_client() {
        let repo = ClientRepository::new(1, 128);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 34567);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let client = repo.allocate_web_client(peer.ip(), peer, local, tx).await;
        assert_eq!(client.get_node_id(), 1);
        assert_eq!(repo.local_len().await, 1);

        let message = text_message("hello");
        client.write_proto_message(&message).await.unwrap();

        let queued = rx.recv().await.unwrap();
        match queued {
            Message::TextMessage(text) => assert_eq!(text.message, "hello"),
            other => panic!("expected TextMessage, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn node_zero_allocation_skips_session_zero() {
        let repo = ClientRepository::new(0, 128);
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 34567);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let client = repo.allocate_web_client(peer.ip(), peer, local, tx).await;

        assert_eq!(client.get_node_id(), 0);
        assert_eq!(client.get_session_id().get_local_session_id(), 1);
        assert_ne!(u32::from(client.get_session_id()), 0);
    }

    #[tokio::test]
    async fn duplicate_numeric_session_ids_are_isolated_by_server_id() {
        let repo_a = ClientRepository::new(1, 128);
        let repo_b = ClientRepository::new(1, 128);
        let peer_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let peer_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30002);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(8);
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(8);

        let alpha = repo_a
            .allocate_web_client_in_server("alpha", peer_a.ip(), peer_a, local, tx_a)
            .await;
        let beta = repo_b
            .allocate_web_client_in_server("beta", peer_b.ip(), peer_b, local, tx_b)
            .await;

        assert_eq!(alpha.get_session_id(), beta.get_session_id());
        assert_ne!(alpha.client_instance_id(), beta.client_instance_id());
        assert_eq!(alpha.server_id(), "alpha");
        assert_eq!(beta.server_id(), "beta");
        assert_eq!(repo_a.local_len_in_server("alpha").await, 1);
        assert_eq!(repo_a.local_len_in_server("beta").await, 0);
        assert!(
            repo_a
                .get_client_in_server("alpha", alpha.get_session_id())
                .await
                .is_some()
        );
        assert!(
            repo_a
                .get_client_in_server("beta", alpha.get_session_id())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn scoped_snapshot_uses_global_local_sequence_baseline() {
        let repo = ClientRepository::new(1, 1);
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);
        let alpha_session = ClientSessionIdentifier::new(1, 7).unwrap();
        let beta_session = ClientSessionIdentifier::new(1, 8).unwrap();

        repo.commit_operation(
            ClientStateOperation::AddClient {
                server_id: "alpha".to_string(),
                session_id: alpha_session,
                client_instance_id: 7,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
            None,
        )
        .await;
        repo.commit_operation(
            ClientStateOperation::AddClient {
                server_id: "beta".to_string(),
                session_id: beta_session,
                client_instance_id: 8,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
            None,
        )
        .await;

        let (_, alpha_versions) = repo.snapshot_with_versions_in_server("alpha").await;
        let (_, beta_versions) = repo.snapshot_with_versions_in_server("beta").await;
        let (_, alpha_auth_versions) = repo
            .published_snapshot_with_versions_in_server("alpha")
            .await
            .into_parts();

        assert_eq!(alpha_versions.get(&1), Some(&2));
        assert_eq!(beta_versions.get(&1), Some(&2));
        assert_eq!(alpha_auth_versions.get(&1), Some(&2));

        let next_alpha_session = ClientSessionIdentifier::new(1, 9).unwrap();
        repo.commit_operation(
            ClientStateOperation::AddClient {
                server_id: "alpha".to_string(),
                session_id: next_alpha_session,
                client_instance_id: 9,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
            None,
        )
        .await;

        let (rebases, entries, versions, _epochs) = repo
            .replay_entries_since_in_server_for_client(
                "alpha",
                &alpha_auth_versions,
                &HashMap::new(),
                ClientSessionIdentifier::new(7, 1).unwrap(),
                700,
            )
            .await
            .into_parts();
        assert!(rebases.is_empty());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version, 3);
        assert_eq!(versions.get(&1), Some(&3));
    }

    #[tokio::test]
    async fn remote_snapshot_uses_materialized_version_for_every_server_scope() {
        let repo = ClientRepository::new(1, 128);
        let alpha = (*remote_add_entry_in_server("alpha", 2, 1, 0).await).clone();
        let beta = (*remote_add_entry_in_server("beta", 2, 2, 0).await).clone();

        assert_eq!(
            repo.install_remote_client_snapshot(
                2,
                7,
                5,
                5,
                vec![alpha, beta],
                &HashMap::from([("alpha".to_owned(), 0), ("beta".to_owned(), 0)]),
            )
            .await
            .unwrap(),
            ClientSnapshotInstallOutcome::Installed
        );

        for server_id in ["alpha", "beta"] {
            let (clients, versions) = repo.snapshot_with_versions_in_server(server_id).await;
            assert_eq!(clients.len(), 1);
            assert_eq!(repo.authenticated_client_count_in_server(server_id), 1);
            assert_eq!(versions.get(&2), Some(&5));
            assert!(
                repo.replay_since_in_server(server_id, &versions)
                    .await
                    .is_ok(),
                "scope {server_id} must not replay from before the remote snapshot floor"
            );
        }
    }

    #[tokio::test]
    async fn empty_remote_snapshot_gives_auth_snapshot_a_replayable_baseline() {
        let repo = ClientRepository::new(1, 128);

        assert_eq!(
            repo.install_remote_client_snapshot(2, 7, 5, 5, Vec::new(), &HashMap::new())
                .await
                .unwrap(),
            ClientSnapshotInstallOutcome::Installed
        );

        let (clients, versions, epochs, _subscription) = repo
            .published_snapshot_with_versions_and_subscription_in_server("empty-scope")
            .await;
        assert!(clients.is_empty());
        assert_eq!(versions.get(&2), Some(&5));
        let plan = repo
            .replay_entries_since_in_server_for_client(
                "empty-scope",
                &versions,
                &epochs,
                ClientSessionIdentifier::new(1, 1).unwrap(),
                1,
            )
            .await;
        assert!(
            plan.rebases().is_empty(),
            "the baseline staged during authentication must not require a rebase"
        );
    }

    #[tokio::test]
    async fn projection_catch_up_rebases_a_cursor_below_the_snapshot_floor() {
        let repo = ClientRepository::new(1, 128);
        let snapshot_entry = (*remote_add_entry_in_server("alpha", 2, 7, 0).await).clone();
        assert_eq!(
            repo.install_remote_client_snapshot(
                2,
                7,
                5,
                5,
                vec![snapshot_entry],
                &HashMap::from([("alpha".to_owned(), 0)]),
            )
            .await
            .unwrap(),
            ClientSnapshotInstallOutcome::Installed
        );

        let plan = repo
            .replay_entries_since_in_server_for_client(
                "alpha",
                &HashMap::from([(2, 0)]),
                &HashMap::from([(2, 7)]),
                ClientSessionIdentifier::new(1, 1).unwrap(),
                1,
            )
            .await;

        assert!(plan.entries().is_empty());
        assert_eq!(plan.target_versions().get(&2), Some(&5));
        assert_eq!(plan.rebases().len(), 1);
        let rebase = &plan.rebases()[0];
        assert_eq!(rebase.origin(), 2);
        assert_eq!(rebase.version(), 5);
        assert_eq!(rebase.entries().len(), 1);
        assert_eq!(rebase.entries()[0].node_id, 2);
        assert_eq!(rebase.entries()[0].version, 5);
        assert_eq!(rebase.entries()[0].op.server_id(), "alpha");
    }

    #[tokio::test]
    async fn projection_catch_up_only_makes_self_state_authoritative_during_rebase() {
        let repo = ClientRepository::new(1, 1);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let viewer = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;
        viewer.set_authenticated(true);

        let (_clients, versions, epochs, _subscription) = repo
            .published_snapshot_with_versions_and_subscription_in_server("alpha")
            .await;
        repo.publish_client_in_server("alpha", viewer.get_session_id())
            .await;

        let contiguous = repo
            .replay_entries_since_in_server_for_client(
                "alpha",
                &versions,
                &epochs,
                viewer.get_session_id(),
                viewer.client_instance_id(),
            )
            .await;
        assert!(contiguous.rebases().is_empty());
        assert!(
            contiguous.entries().is_empty(),
            "the viewer's ordinary published AddClient must not become a self update"
        );

        repo.commit_operation(
            ClientStateOperation::UpdateGlobalState {
                server_id: "alpha".to_owned(),
                session_id: viewer.get_session_id(),
                client_instance_id: viewer.client_instance_id(),
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    display_name: Some(Some("authoritative".to_owned())),
                    ..Default::default()
                },
            },
            None,
        )
        .await;

        let rebased = repo
            .replay_entries_since_in_server_for_client(
                "alpha",
                &versions,
                &epochs,
                viewer.get_session_id(),
                viewer.client_instance_id(),
            )
            .await;
        assert_eq!(rebased.rebases().len(), 1);
        assert!(matches!(
            &rebased.rebases()[0].entries()[0].op,
            ClientStateOperation::UpdateGlobalState {
                session_id,
                client_instance_id,
                ..
            } if *session_id == viewer.get_session_id()
                && *client_instance_id == viewer.client_instance_id()
        ));
    }

    #[tokio::test]
    async fn projection_catch_up_rebases_when_remote_epoch_changes_at_the_same_version() {
        let repo = ClientRepository::new(1, 128);
        repo.apply_remote_operation_with_epoch(10, remote_add_entry(2, 1, 1).await, 0)
            .await
            .expect("old epoch add");

        let (_clients, versions, epochs, _subscription) = repo
            .published_snapshot_with_versions_and_subscription_in_server("alpha")
            .await;
        assert_eq!(versions.get(&2), Some(&1));
        assert_eq!(epochs.get(&2), Some(&10));

        repo.apply_remote_operation_with_epoch(11, remote_add_entry(2, 2, 1).await, 0)
            .await
            .expect("new epoch add at reused version");

        let plan = repo
            .replay_entries_since_in_server_for_client(
                "alpha",
                &versions,
                &epochs,
                ClientSessionIdentifier::new(1, 1).unwrap(),
                1,
            )
            .await;

        assert!(plan.entries().is_empty());
        assert_eq!(plan.target_versions().get(&2), Some(&1));
        assert_eq!(plan.target_epochs().get(&2), Some(&11));
        assert_eq!(plan.rebases().len(), 1);
        let rebase = &plan.rebases()[0];
        assert_eq!(rebase.origin(), 2);
        assert_eq!(rebase.version(), 1);
        assert_eq!(rebase.epoch(), Some(11));
        assert_eq!(rebase.entries().len(), 1);
        assert!(matches!(
            &rebase.entries()[0].op,
            ClientStateOperation::AddClient { session_id, .. }
                if *session_id == ClientSessionIdentifier::new(2, 2).unwrap()
        ));
    }

    #[tokio::test]
    async fn projection_catch_up_advances_past_out_of_scope_only_suffix() {
        let repo = ClientRepository::new(1, 128);
        for version in 1..=2 {
            repo.apply_remote_operation_with_epoch(
                7,
                remote_add_entry_in_server("beta", 2, version as u32, version).await,
                0,
            )
            .await
            .unwrap();
        }

        let plan = repo
            .replay_entries_since_in_server_for_client(
                "alpha",
                &HashMap::from([(2, 0)]),
                &HashMap::from([(2, 7)]),
                ClientSessionIdentifier::new(1, 1).unwrap(),
                1,
            )
            .await;

        assert!(plan.rebases().is_empty());
        assert!(plan.entries().is_empty());
        assert_eq!(plan.target_versions().get(&2), Some(&2));
    }

    #[tokio::test]
    async fn projection_catch_up_rebases_empty_and_unrelated_snapshots_without_scoped_entries() {
        for (node_id, snapshot_entries, scope_versions) in [
            (2, Vec::new(), HashMap::new()),
            (
                3,
                vec![(*remote_add_entry_in_server("beta", 3, 7, 0).await).clone()],
                HashMap::from([("beta".to_owned(), 0)]),
            ),
        ] {
            let repo = ClientRepository::new(1, 128);
            assert_eq!(
                repo.install_remote_client_snapshot(
                    node_id,
                    7,
                    5,
                    5,
                    snapshot_entries,
                    &scope_versions,
                )
                .await
                .unwrap(),
                ClientSnapshotInstallOutcome::Installed
            );

            let plan = repo
                .replay_entries_since_in_server_for_client(
                    "alpha",
                    &HashMap::from([(node_id, 0)]),
                    &HashMap::from([(node_id, 7)]),
                    ClientSessionIdentifier::new(1, 1).unwrap(),
                    1,
                )
                .await;

            assert!(plan.entries().is_empty());
            assert_eq!(plan.target_versions().get(&node_id), Some(&5));
            assert_eq!(plan.rebases().len(), 1);
            let rebase = &plan.rebases()[0];
            assert_eq!(rebase.origin(), node_id);
            assert_eq!(rebase.version(), 5);
            assert!(rebase.entries().is_empty());
        }
    }

    #[tokio::test]
    async fn subscribed_snapshot_receives_followup_client_state_entries() {
        let repo = ClientRepository::new(1, 128);
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);
        let session = ClientSessionIdentifier::new(1, 9).unwrap();

        let (_clients, versions, mut rx) = repo
            .snapshot_with_versions_and_subscription_in_server("alpha")
            .await;
        assert!(versions.is_empty());

        repo.commit_operation(
            ClientStateOperation::AddClient {
                server_id: "alpha".to_string(),
                session_id: session,
                client_instance_id: 9,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
            None,
        )
        .await;

        let broadcast = rx
            .try_recv()
            .expect("snapshot subscription receives commit");
        assert_eq!(broadcast.entry.version, 1);
        assert_eq!(broadcast.entry.op.server_id(), "alpha");
    }

    #[tokio::test]
    async fn published_snapshot_excludes_authenticated_unpublished_local_clients() {
        let repo = ClientRepository::new(1, 128);
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let local_addr = SocketAddr::new(real_ip, 64738);
        let (pending_tx, _pending_rx) = tokio::sync::mpsc::channel(8);
        let pending = repo
            .allocate_web_client_in_server(
                "alpha",
                real_ip,
                SocketAddr::new(real_ip, 30001),
                local_addr,
                pending_tx,
            )
            .await;
        pending.set_authenticated(true);

        let (clients, versions, _epochs, mut rx) = repo
            .published_snapshot_with_versions_and_subscription_in_server("alpha")
            .await;
        assert!(clients.is_empty());
        assert!(versions.is_empty());

        repo.publish_client_in_server("alpha", pending.get_session_id())
            .await;
        let broadcast = rx.recv().await.expect("published AddClient broadcast");
        assert_eq!(broadcast.entry.version, 1);
        assert!(matches!(
            broadcast.entry.op,
            ClientStateOperation::AddClient { .. }
        ));

        let (clients, versions) = repo
            .published_snapshot_with_versions_in_server("alpha")
            .await
            .into_parts();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].get_session_id(), pending.get_session_id());
        assert_eq!(versions.get(&1), Some(&1));
    }

    #[tokio::test]
    async fn async_commit_waits_for_transient_register_contention() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);
        let session = ClientSessionIdentifier::new(1, 9).unwrap();
        let guard = repo.register.write().await;

        let mut commit = tokio::spawn({
            let repo = Arc::clone(&repo);
            async move {
                repo.commit_operation(
                    ClientStateOperation::AddClient {
                        server_id: "alpha".to_string(),
                        session_id: session,
                        client_instance_id: 9,
                        real_ip,
                        tcp_addr,
                        udp_addr: None,
                        local_addr,
                        cert_hash: None,
                        login_time: Utc::now(),
                        initial_state: ClientGlobalStateDelta::default(),
                    },
                    None,
                )
                .await;
            }
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut commit)
                .await
                .is_err(),
            "async commits should wait for the register lock instead of dropping the op"
        );
        drop(guard);

        commit.await.unwrap();
        assert_eq!(repo.current_version(), 1);
    }

    #[tokio::test]
    async fn remote_node_lock_contention_does_not_block_local_or_other_remote_nodes() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        repo.allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;

        repo.apply_remote_operation(remote_add_entry(2, 1, 1).await, 0)
            .await
            .unwrap();
        repo.apply_remote_operation(remote_add_entry(3, 1, 1).await, 0)
            .await
            .unwrap();

        let blocked = repo.get_or_create_remote_register(2).await;
        let _blocked_guard = blocked.write().await;

        let local_count =
            tokio::time::timeout(Duration::from_millis(50), repo.local_len_in_server("alpha"))
                .await
                .expect("local reads should not wait for a blocked remote shard");
        assert_eq!(local_count, 1);

        let node3_session = ClientSessionIdentifier::new(3, 1).unwrap();
        let node3_client = tokio::time::timeout(
            Duration::from_millis(50),
            repo.get_client_in_server("alpha", node3_session),
        )
        .await
        .expect("another remote node should not wait for a blocked remote shard");
        assert!(node3_client.is_some());
    }

    #[tokio::test]
    async fn out_of_order_remote_versions_are_buffered_without_dropping_gap_fill() {
        let repo = ClientRepository::new(1, 128);

        repo.apply_remote_operation(remote_add_entry(2, 2, 2).await, 0)
            .await
            .unwrap();
        assert!(
            repo.get_client_in_server("alpha", ClientSessionIdentifier::new(2, 2).unwrap())
                .await
                .is_none()
        );

        repo.apply_remote_operation(remote_add_entry(2, 1, 1).await, 0)
            .await
            .unwrap();
        assert!(
            repo.get_client_in_server("alpha", ClientSessionIdentifier::new(2, 1).unwrap())
                .await
                .is_some()
        );
        assert!(
            repo.get_client_in_server("alpha", ClientSessionIdentifier::new(2, 2).unwrap())
                .await
                .is_none()
        );

        repo.drain_pending_ops("alpha", 0).await;
        assert!(
            repo.get_client_in_server("alpha", ClientSessionIdentifier::new(2, 2).unwrap())
                .await
                .is_some()
        );
        assert_eq!(repo.snapshot_with_versions().await.1.get(&2), Some(&2));
    }

    #[tokio::test]
    async fn broadcast_all_does_not_hold_register_lock_while_writing() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let client = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;
        client
            .write_proto_message(&text_message("prefill"))
            .await
            .unwrap();
        let message = text_message("blocked broadcast");

        let broadcast = tokio::spawn({
            let repo = Arc::clone(&repo);
            let message = message.clone();
            async move {
                repo.broadcast_all_in_server("alpha", &message).await;
            }
        });
        tokio::task::yield_now().await;

        assert_register_read_completes_while_write_is_queued(&repo, 1).await;

        broadcast.abort();
        let _ = broadcast.await;
    }

    #[tokio::test]
    async fn broadcast_except_does_not_hold_register_lock_while_writing() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let peer_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let peer_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30002);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(1);
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(1);
        let excluded = repo
            .allocate_web_client_in_server("alpha", peer_a.ip(), peer_a, local, tx_a)
            .await;
        let target = repo
            .allocate_web_client_in_server("alpha", peer_b.ip(), peer_b, local, tx_b)
            .await;
        target
            .write_proto_message(&text_message("prefill"))
            .await
            .unwrap();
        let message = text_message("blocked broadcast except");

        let broadcast = tokio::spawn({
            let repo = Arc::clone(&repo);
            let message = message.clone();
            let excluded = excluded.get_session_id();
            async move {
                repo.broadcast_except_in_server("alpha", excluded, &message)
                    .await;
            }
        });
        tokio::task::yield_now().await;

        assert_register_read_completes_while_write_is_queued(&repo, 2).await;

        broadcast.abort();
        let _ = broadcast.await;
    }

    #[tokio::test]
    async fn broadcast_batch_except_does_not_hold_register_lock_while_writing() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let peer_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let peer_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30002);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(1);
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(1);
        let excluded = repo
            .allocate_web_client_in_server("alpha", peer_a.ip(), peer_a, local, tx_a)
            .await;
        let target = repo
            .allocate_web_client_in_server("alpha", peer_b.ip(), peer_b, local, tx_b)
            .await;
        target
            .write_proto_message(&text_message("prefill"))
            .await
            .unwrap();
        let messages = vec![text_message("blocked batch broadcast")];

        let broadcast = tokio::spawn({
            let repo = Arc::clone(&repo);
            let messages = messages.clone();
            let excluded = excluded.get_session_id();
            async move {
                repo.broadcast_batch_except_in_server("alpha", excluded, &messages)
                    .await;
            }
        });
        tokio::task::yield_now().await;

        assert_register_read_completes_while_write_is_queued(&repo, 2).await;

        broadcast.abort();
        let _ = broadcast.await;
    }

    #[tokio::test]
    async fn replay_since_does_not_hold_register_lock_while_building_messages() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;
        client.set_published(true);
        commit_alpha_add_client(&repo, client.get_session_id(), client.client_instance_id()).await;

        let replay = tokio::spawn({
            let repo = Arc::clone(&repo);
            async move {
                let (messages, versions) = repo
                    .replay_since_in_server("alpha", &HashMap::new())
                    .await
                    .expect("replay succeeds");
                assert_eq!(messages.len(), 1);
                assert_eq!(versions.get(&1), Some(&1));
            }
        });
        tokio::task::yield_now().await;

        assert_register_read_completes_while_write_is_queued(&repo, 1).await;

        replay.await.unwrap();
    }

    #[tokio::test]
    async fn udp_bindings_are_scoped_by_local_endpoint() {
        let repo = ClientRepository::new(1, 128);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let local_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let local_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64748);
        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(8);
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(8);

        let alpha = repo
            .allocate_web_client_in_server("alpha", remote.ip(), remote, local_a, tx_a)
            .await;
        let beta = repo
            .allocate_web_client_in_server("beta", remote.ip(), remote, local_b, tx_b)
            .await;

        repo.bind_client_udp_endpoint_in_server(
            "alpha",
            alpha.get_session_id(),
            Some(local_a),
            remote,
        )
        .await;
        repo.bind_client_udp_endpoint_in_server(
            "beta",
            beta.get_session_id(),
            Some(local_b),
            remote,
        )
        .await;

        assert_eq!(
            repo.get_client_by_udp_endpoint(local_a, remote)
                .await
                .unwrap()
                .server_id(),
            "alpha"
        );
        assert_eq!(
            repo.get_client_by_udp_endpoint(local_b, remote)
                .await
                .unwrap()
                .server_id(),
            "beta"
        );
    }

    #[tokio::test]
    async fn pending_remote_client_ops_wait_on_matching_server_channel_version() {
        let repo = ClientRepository::new(1, 128);
        let remote_session = ClientSessionIdentifier::new(2, 7).unwrap();
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);

        let alpha_add = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: Some(5),
            op: ClientStateOperation::AddClient {
                server_id: "alpha".to_string(),
                session_id: remote_session,
                client_instance_id: 7,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        });
        let beta_update = Arc::new(ClientStateLogEntry {
            version: 2,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: Some(5),
            op: ClientStateOperation::UpdateGlobalState {
                server_id: "beta".to_string(),
                session_id: remote_session,
                client_instance_id: 7,
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    display_name: Some(Some("beta user".to_string())),
                    ..Default::default()
                },
            },
        });

        repo.apply_remote_operation(alpha_add, 4).await.unwrap();
        repo.apply_remote_operation(beta_update, 5).await.unwrap();

        assert!(
            repo.get_client_in_server("alpha", remote_session)
                .await
                .is_none()
        );

        repo.drain_pending_ops("beta", 5).await;
        assert!(
            repo.get_client_in_server("alpha", remote_session)
                .await
                .is_none()
        );

        repo.drain_pending_ops("alpha", 5).await;
        assert!(
            repo.get_client_in_server("alpha", remote_session)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn remote_update_global_state_mutates_remote_client() {
        let repo = ClientRepository::new(1, 128);
        let remote_session = ClientSessionIdentifier::new(2, 7).unwrap();
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);

        let add = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: crate::types::default_server_id(),
                session_id: remote_session,
                client_instance_id: 7,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        });
        let update = Arc::new(ClientStateLogEntry {
            version: 2,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: Some(1),
            op: ClientStateOperation::UpdateGlobalState {
                server_id: crate::types::default_server_id(),
                session_id: remote_session,
                client_instance_id: 7,
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    current_channel_id: Some(42),
                    ..Default::default()
                },
            },
        });

        repo.apply_remote_operation(add, 1).await.unwrap();
        repo.apply_remote_operation(update, 1).await.unwrap();

        let client = repo
            .get_client_in_server(&crate::types::default_server_id(), remote_session)
            .await
            .expect("remote client should be materialized");
        assert_eq!(client.get_current_channel_id(), 42);
        assert_eq!(repo.snapshot_with_versions().await.1.get(&2), Some(&2));
    }

    #[tokio::test]
    async fn stale_remove_client_does_not_remove_reused_session_instance() {
        let repo = ClientRepository::new(1, 128);
        let remote_session = ClientSessionIdentifier::new(2, 7).unwrap();
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);
        let live_instance_id = 22;

        let client = Arc::new(Client::new_remote_in_server(
            crate::types::default_server_id(),
            remote_session,
            real_ip,
            tcp_addr,
            None,
            local_addr,
            None,
            Utc::now(),
            live_instance_id,
        ));
        repo.add_remote_client(remote_session, client).await;

        let stale_remove = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::RemoveClient {
                server_id: crate::types::default_server_id(),
                session_id: remote_session,
                client_instance_id: 11,
                actor: None,
                reason: None,
                ban: false,
            },
        });

        repo.apply_remote_operation(Arc::clone(&stale_remove), 0)
            .await
            .unwrap();
        assert!(
            repo.get_client_in_server(&crate::types::default_server_id(), remote_session)
                .await
                .is_some()
        );
        assert!(stale_remove.to_message(&repo).await.is_none());
    }

    #[tokio::test]
    async fn removing_last_direct_remote_client_retains_shard_for_safe_reuse() {
        let repo = ClientRepository::new(1, 128);
        let remote_session = ClientSessionIdentifier::new(2, 7).unwrap();
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);

        let first = Arc::new(Client::new_remote_in_server(
            "alpha".to_owned(),
            remote_session,
            real_ip,
            tcp_addr,
            None,
            local_addr,
            None,
            Utc::now(),
            7,
        ));
        repo.add_remote_client(remote_session, first).await;

        let retained = repo
            .get_remote_register(2)
            .await
            .expect("remote shard exists after insertion");
        repo.remove_client_in_server("alpha", remote_session)
            .await
            .expect("remote client is removed");

        assert_eq!(repo.authenticated_client_count_in_server("alpha"), 0);
        assert!(retained.read().await.clients.is_empty());
        assert!(Arc::ptr_eq(
            &retained,
            &repo
                .get_remote_register(2)
                .await
                .expect("empty remote shard remains registered")
        ));

        let replacement = Arc::new(Client::new_remote_in_server(
            "alpha".to_owned(),
            remote_session,
            real_ip,
            tcp_addr,
            None,
            local_addr,
            None,
            Utc::now(),
            8,
        ));
        repo.add_remote_client(remote_session, replacement).await;

        assert_eq!(repo.authenticated_client_count_in_server("alpha"), 1);
        assert_eq!(
            repo.get_client_in_server("alpha", remote_session)
                .await
                .expect("replacement client is visible")
                .client_instance_id(),
            8
        );
    }

    #[tokio::test]
    async fn voice_recipient_index_snapshot_is_scoped_to_all_servers() {
        let repo = ClientRepository::new(1, 128);
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let local_addr = SocketAddr::new(real_ip, 64738);
        let peer_alpha = SocketAddr::new(real_ip, 30001);
        let peer_beta = SocketAddr::new(real_ip, 30002);
        let (tx_alpha, _rx_alpha) = tokio::sync::mpsc::channel(8);
        let (tx_beta, _rx_beta) = tokio::sync::mpsc::channel(8);

        let alpha = repo
            .allocate_web_client_in_server("alpha", real_ip, peer_alpha, local_addr, tx_alpha)
            .await;
        let beta = repo
            .allocate_web_client_in_server("beta", real_ip, peer_beta, local_addr, tx_beta)
            .await;
        alpha.set_current_channel_id(42, &repo, 1);
        beta.set_current_channel_id(42, &repo, 1);

        let remote_session = ClientSessionIdentifier::new(2, 7).unwrap();
        let remote_add = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: "beta".to_owned(),
                session_id: remote_session,
                client_instance_id: 7,
                real_ip,
                tcp_addr: SocketAddr::new(real_ip, 30003),
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta {
                    current_channel_id: Some(42),
                    listening_channel_add: Some([84].into_iter().collect()),
                    ..Default::default()
                },
            },
        });
        repo.apply_remote_operation(remote_add, 1).await.unwrap();

        let snapshot = repo.voice_recipient_index_snapshot().await;
        let alpha_nodes = snapshot
            .get(&RecipientIndexKey::new("alpha", 42))
            .expect("alpha channel 42 is tracked");
        assert_eq!(alpha_nodes, &std::collections::BTreeSet::from([1]));

        let beta_nodes = snapshot
            .get(&RecipientIndexKey::new("beta", 42))
            .expect("beta channel 42 is tracked separately");
        assert_eq!(beta_nodes, &std::collections::BTreeSet::from([1, 2]));

        let beta_listener_nodes = snapshot
            .get(&RecipientIndexKey::new("beta", 84))
            .expect("beta listener channel is tracked");
        assert_eq!(beta_listener_nodes, &std::collections::BTreeSet::from([2]));
        assert!(!snapshot.contains_key(&RecipientIndexKey::new("alpha", 84)));
    }

    #[tokio::test]
    async fn clear_clients_from_node_broadcasts_global_origin_reset_without_local_log() {
        let repo = ClientRepository::new(1, 128);
        let mut rx = repo.subscribe();
        let remote_session = ClientSessionIdentifier::new(2, 7).unwrap();
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);

        let add = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: crate::types::default_server_id(),
                session_id: remote_session,
                client_instance_id: 22,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        });

        repo.apply_remote_operation(add, 0).await.unwrap();
        let _ = rx.recv().await.expect("add broadcast");
        assert!(repo.get_client(remote_session).await.is_some());
        assert_eq!(repo.current_version(), 0);

        repo.clear_clients_from_node(2).await;

        assert!(repo.get_client(remote_session).await.is_none());
        assert_eq!(
            repo.authenticated_client_count_in_server(crate::types::DEFAULT_SERVER_ID),
            0
        );
        assert_eq!(repo.current_version(), 0);

        let payload = rx.recv().await.expect("global reset broadcast");
        assert_eq!(payload.entry.node_id, 2);
        assert_eq!(payload.entry.version, 1);
        assert_eq!(payload.versions.get(&2), Some(&0));
        assert!(matches!(
            payload.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        assert!(payload.entry.to_message(&repo).await.is_none());

        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let client = repo
            .allocate_web_client(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30002),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738),
                tx,
            )
            .await;
        client
            .update_last_client_versions(&HashMap::from([(2, 1)]))
            .await;
        client.update_last_client_versions(&payload.versions).await;
        assert!(!client.get_last_client_versions().await.contains_key(&2));
    }

    #[tokio::test]
    async fn clear_clients_from_node_drops_stale_remote_version_after_client_already_removed() {
        let repo = ClientRepository::new(1, 128);
        let remote_session = ClientSessionIdentifier::new(2, 7).unwrap();
        let real_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let tcp_addr = SocketAddr::new(real_ip, 30001);
        let local_addr = SocketAddr::new(real_ip, 64738);

        let old_add = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: crate::types::default_server_id(),
                session_id: remote_session,
                client_instance_id: 22,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        });
        let old_remove = Arc::new(ClientStateLogEntry {
            version: 2,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::RemoveClient {
                server_id: crate::types::default_server_id(),
                session_id: remote_session,
                client_instance_id: 22,
                actor: None,
                reason: None,
                ban: false,
            },
        });

        repo.apply_remote_operation(old_add, 0).await.unwrap();
        repo.apply_remote_operation(old_remove, 0).await.unwrap();
        assert!(repo.get_client(remote_session).await.is_none());
        assert_eq!(repo.snapshot_with_versions().await.1.get(&2), Some(&2));

        let mut rx = repo.subscribe();
        repo.clear_clients_from_node(2).await;
        assert!(!repo.snapshot_with_versions().await.1.contains_key(&2));
        let reset = rx.recv().await.expect("reset broadcast");
        assert_eq!(reset.entry.node_id, 2);
        assert_eq!(reset.entry.version, 1);
        assert_eq!(reset.versions.get(&2), Some(&0));
        assert!(matches!(
            reset.entry.op,
            ClientStateOperation::ResetNode { .. }
        ));
        assert!(reset.entry.to_message(&repo).await.is_none());

        let restarted_add = Arc::new(ClientStateLogEntry {
            version: 1,
            node_id: 2,
            timestamp: Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: crate::types::default_server_id(),
                session_id: remote_session,
                client_instance_id: 33,
                real_ip,
                tcp_addr,
                udp_addr: None,
                local_addr,
                cert_hash: None,
                login_time: Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        });

        assert!(
            repo.apply_remote_operation(Arc::clone(&restarted_add), 0)
                .await
                .is_err(),
            "same-epoch version reuse is fenced after an offline removal"
        );
        repo.reset_clients_from_node(2, 1).await;
        repo.apply_remote_operation_with_epoch(1, restarted_add, 0)
            .await
            .unwrap();
        let client = repo
            .get_client(remote_session)
            .await
            .expect("restarted node's version-1 client add should apply");
        assert_eq!(client.client_instance_id(), 33);
        assert_eq!(repo.snapshot_with_versions().await.1.get(&2), Some(&1));
    }

    #[tokio::test]
    async fn client_instance_id_is_not_reused_while_old_operations_are_retained() {
        let repo = ClientRepository::new(1, 128);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30003);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(8);

        let client = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;
        let instance_id = client.client_instance_id();

        repo.publish_client_in_server("alpha", client.get_session_id())
            .await;
        repo.remove_client_in_server("alpha", client.get_session_id())
            .await;

        let (replacement_tx, _replacement_rx) = tokio::sync::mpsc::channel(8);
        let replacement = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, replacement_tx)
            .await;

        let register = repo.register.read().await;
        assert!(
            register
                .local_log
                .iter()
                .any(|entry| entry.op.client_instance_id() == instance_id),
            "the old instance ID should still be retained in the operation log"
        );
        assert_ne!(replacement.client_instance_id(), 0);
        assert_ne!(replacement.client_instance_id(), instance_id);
    }

    #[tokio::test]
    async fn active_local_session_id_is_not_reallocated() {
        let repo = ClientRepository::new(1, 8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30003);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (old_tx, _old_rx) = tokio::sync::mpsc::channel(8);

        let old = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, old_tx)
            .await;
        let old_session = old.get_session_id();
        repo.publish_client_in_server("alpha", old_session).await;

        let (new_tx, _new_rx) = tokio::sync::mpsc::channel(8);
        let new_client = repo
            .allocate_web_client_in_server(
                "alpha",
                peer.ip(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30004),
                local,
                new_tx,
            )
            .await;

        assert_ne!(
            new_client.get_session_id(),
            old_session,
            "session IDs remain held until the owning client is removed"
        );
    }

    #[tokio::test]
    async fn remove_client_log_returns_local_session_id_to_pool() {
        let repo = ClientRepository::new(1, 8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30003);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (old_tx, _old_rx) = tokio::sync::mpsc::channel(8);

        let old = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, old_tx)
            .await;
        let old_session = old.get_session_id();
        repo.publish_client_in_server("alpha", old_session).await;
        repo.remove_client_in_server("alpha", old_session).await;

        let (new_tx, _new_rx) = tokio::sync::mpsc::channel(8);
        let new_client = repo
            .allocate_web_client_in_server(
                "alpha",
                peer.ip(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30004),
                local,
                new_tx,
            )
            .await;

        assert_eq!(
            new_client.get_session_id(),
            old_session,
            "committed RemoveClient returns the session ID to the free pool"
        );
    }

    #[tokio::test]
    async fn unpublished_global_state_update_is_not_deferred_past_publish() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let mut rx = repo.subscribe();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30004);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let client = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;
        let session = client.get_session_id();

        let write_guard = repo.register.write().await;
        {
            let mut gs = client.write_global_state(&repo);
            gs.set_display_name(Some("alice".to_string()));
            gs.set_user_id(Some(7));
        }
        drop(write_guard);

        assert_eq!(repo.current_version(), 0);
        assert!(rx.try_recv().is_err());

        repo.publish_client_in_server("alpha", session).await;
        let payload = rx.recv().await.expect("AddClient broadcast");
        match &payload.entry.op {
            ClientStateOperation::AddClient {
                session_id,
                initial_state,
                ..
            } => {
                assert_eq!(*session_id, session);
                assert_eq!(initial_state.display_name, Some(Some("alice".to_string())));
                assert_eq!(initial_state.user_id, Some(Some(7)));
            }
            other => panic!("expected AddClient, got {other:?}"),
        }
        assert!(rx.try_recv().is_err());

        let log = repo.get_log_since(0).await;
        assert_eq!(log.len(), 1);
        assert!(matches!(log[0].op, ClientStateOperation::AddClient { .. }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_commits_wait_for_deferred_global_state_commits() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30004);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let client = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;
        let session = client.get_session_id();
        repo.publish_client_in_server("alpha", session).await;
        let base_version = repo.current_version_in_server("alpha");

        let write_guard = repo.register.write().await;
        {
            let mut gs = client.write_global_state(&repo);
            gs.set_current_channel_id(10);
        }
        drop(write_guard);

        repo.remove_client_in_server("alpha", session).await;

        let ops: Vec<&'static str> = repo
            .get_log_since(base_version)
            .await
            .iter()
            .filter_map(|entry| match &entry.op {
                ClientStateOperation::UpdateGlobalState { delta, .. } => {
                    assert_eq!(delta.current_channel_id, Some(10));
                    Some("move")
                }
                ClientStateOperation::RemoveClient { .. } => Some("remove"),
                _ => None,
            })
            .collect();
        assert_eq!(ops, vec!["move", "remove"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_projection_rebase_waits_for_deferred_state_commit() {
        let repo = Arc::new(ClientRepository::new(1, 1));
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30005);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let client = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;
        let session = client.get_session_id();
        repo.publish_client_in_server("alpha", session).await;
        {
            let mut state = client.write_global_state(&repo);
            state.set_display_name(Some("before-rebase".to_owned()));
        }

        let write_guard = repo.register.write().await;
        {
            let mut state = client.write_global_state(&repo);
            state.set_current_channel_id(42);
        }

        let catch_up = tokio::spawn({
            let repo = Arc::clone(&repo);
            async move {
                repo.replay_entries_since_in_server_for_client(
                    "alpha",
                    &HashMap::from([(1, 0)]),
                    &HashMap::new(),
                    ClientSessionIdentifier::new(1, 999).unwrap(),
                    999,
                )
                .await
            }
        });
        tokio::task::yield_now().await;
        assert!(
            !catch_up.is_finished(),
            "catch-up must wait until the matching state commit is materialized"
        );

        drop(write_guard);
        let plan = catch_up.await.unwrap();
        assert_eq!(plan.target_versions().get(&1), Some(&3));
        assert_eq!(plan.rebases().len(), 1);
        let entries = plan.rebases()[0].entries();
        assert_eq!(entries.len(), 1);
        match &entries[0].op {
            ClientStateOperation::AddClient { initial_state, .. } => {
                assert_eq!(initial_state.current_channel_id, Some(42));
            }
            other => panic!("expected AddClient, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deferred_global_state_commits_keep_fifo_order_after_contention() {
        let repo = Arc::new(ClientRepository::new(1, 128));
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30004);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let client = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, tx)
            .await;
        let session = client.get_session_id();
        repo.publish_client_in_server("alpha", session).await;
        let base_version = repo.current_version_in_server("alpha");

        let write_guard = repo.register.write().await;
        {
            let mut gs = client.write_global_state(&repo);
            gs.set_current_channel_id(10);
        }
        drop(write_guard);
        {
            let mut gs = client.write_global_state(&repo);
            gs.set_current_channel_id(20);
        }

        assert_eq!(
            repo.current_version_in_server("alpha"),
            base_version,
            "newer synchronous commits must queue behind a deferred older commit"
        );

        for _ in 0..10 {
            if repo.current_version_in_server("alpha") >= base_version + 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(repo.current_version_in_server("alpha"), base_version + 2);

        let moves: Vec<u32> = repo
            .get_log_since(base_version)
            .await
            .into_iter()
            .filter_map(|entry| match &entry.op {
                ClientStateOperation::UpdateGlobalState { delta, .. } => delta.current_channel_id,
                _ => None,
            })
            .collect();
        assert_eq!(moves, vec![10, 20]);
    }

    #[tokio::test]
    async fn reused_session_does_not_replay_stale_state_as_current_self() {
        let repo = ClientRepository::new(1, 128);
        let (old_tx, _old_rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30005);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let old = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, old_tx)
            .await;
        let session = old.get_session_id();
        let old_instance = old.client_instance_id();
        {
            let mut gs = old.write_global_state_direct();
            gs.set_display_name(Some("old-user".to_string()));
            gs.set_user_id(Some(101));
        }
        repo.publish_client_in_server("alpha", session).await;
        {
            let mut gs = old.write_global_state(&repo);
            gs.set_display_name(Some("old-user-renamed".to_string()));
            gs.set_user_id(Some(102));
        }
        repo.remove_client_in_server("alpha", session).await;

        let (new_tx, _new_rx) = tokio::sync::mpsc::channel(8);
        let new_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30006);
        let new_client = repo
            .allocate_web_client_in_server("alpha", new_peer.ip(), new_peer, local, new_tx)
            .await;
        assert_eq!(new_client.get_session_id(), session);
        assert_ne!(new_client.client_instance_id(), old_instance);
        {
            let mut gs = new_client.write_global_state_direct();
            gs.set_display_name(Some("new-user".to_string()));
            gs.set_user_id(Some(202));
        }

        let last_seen = HashMap::new();
        let (messages, versions) = repo
            .replay_since_in_server_for_client(
                "alpha",
                &last_seen,
                session,
                new_client.client_instance_id(),
            )
            .await
            .expect("message replay succeeds");
        assert!(
            messages.iter().all(|message| {
                !matches!(
                    message,
                    shitspeak_messages::messages::Message::UserState(state)
                        if state.session == Some(u32::from(session))
                            && matches!(
                                (state.name.as_deref(), state.user_id),
                                (Some("old-user"), Some(101))
                                    | (Some("old-user-renamed"), Some(102))
                            )
                )
            }),
            "stale identity state for the previous occupant must not replay as the new client's self UserState"
        );
        assert_eq!(versions.get(&1), Some(&3));

        let (rebases, entries, entry_versions, _entry_epochs) = repo
            .replay_entries_since_in_server_for_client(
                "alpha",
                &last_seen,
                &HashMap::new(),
                session,
                new_client.client_instance_id(),
            )
            .await
            .into_parts();
        assert!(rebases.is_empty());
        for entry in &entries {
            let entry_messages = entry
                .messages_for_client(&repo, session, new_client.client_instance_id())
                .await;
            assert!(
                entry_messages.iter().all(|message| {
                    !matches!(
                        message,
                        shitspeak_messages::messages::Message::UserState(state)
                            if state.session == Some(u32::from(session))
                                && matches!(
                                    (state.name.as_deref(), state.user_id),
                                    (Some("old-user"), Some(101))
                                        | (Some("old-user-renamed"), Some(102))
                                )
                    )
                }),
                "stale retained log entry must not produce a self UserState for the new session occupant"
            );
        }
        assert_eq!(entry_versions.get(&1), Some(&3));

        let stale_add = repo
            .get_log_since(0)
            .await
            .into_iter()
            .find(|entry| {
                matches!(
                    &entry.op,
                    ClientStateOperation::AddClient {
                        session_id,
                        client_instance_id,
                        ..
                    } if *session_id == session && *client_instance_id == old_instance
                )
            })
            .expect("old AddClient retained in local log");
        assert!(
            stale_add.to_message(&repo).await.is_none(),
            "stale AddClient with a reused session must not convert to UserState"
        );
        let stale_update = repo
            .get_log_since(0)
            .await
            .into_iter()
            .find(|entry| {
                matches!(
                    &entry.op,
                    ClientStateOperation::UpdateGlobalState {
                        session_id,
                        client_instance_id,
                        ..
                    } if *session_id == session && *client_instance_id == old_instance
                )
            })
            .expect("old UpdateGlobalState retained in local log");
        assert!(
            stale_update.to_message(&repo).await.is_none(),
            "stale UpdateGlobalState with a reused session must not convert to UserState"
        );
    }

    #[tokio::test]
    async fn stale_instance_update_does_not_publish_for_reused_session() {
        let repo = ClientRepository::new(1, 128);
        let (old_tx, _old_rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30009);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let old = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, old_tx)
            .await;
        let session = old.get_session_id();
        let old_instance = old.client_instance_id();
        repo.publish_client_in_server("alpha", session).await;
        repo.remove_client_instance_in_server("alpha", session, old_instance)
            .await
            .expect("old client removed");

        let (new_tx, _new_rx) = tokio::sync::mpsc::channel(8);
        let new_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30010);
        let new_client = repo
            .allocate_web_client_in_server("alpha", new_peer.ip(), new_peer, local, new_tx)
            .await;
        assert_eq!(new_client.get_session_id(), session);
        repo.publish_client_in_server("alpha", session).await;
        let version_before_stale_update = repo.current_version();

        {
            let mut state = old.write_global_state(&repo);
            state.set_display_name(Some("stale identity".to_owned()));
            state.set_user_id(Some(999));
        }

        assert_eq!(repo.current_version(), version_before_stale_update);
        assert_eq!(new_client.display_name_opt(), None);
        assert_eq!(new_client.get_user_id(), None);
        assert!(
            repo.get_log_since(version_before_stale_update)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn stale_instance_removal_does_not_remove_reused_session() {
        let repo = ClientRepository::new(1, 128);
        let (old_tx, _old_rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30007);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let old = repo
            .allocate_web_client_in_server("alpha", peer.ip(), peer, local, old_tx)
            .await;
        let session = old.get_session_id();
        let old_instance = old.client_instance_id();
        repo.publish_client_in_server("alpha", session).await;
        assert!(
            repo.remove_client_instance_in_server("alpha", session, old_instance)
                .await
                .is_some()
        );

        let (new_tx, _new_rx) = tokio::sync::mpsc::channel(8);
        let new_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30008);
        let new_client = repo
            .allocate_web_client_in_server("alpha", new_peer.ip(), new_peer, local, new_tx)
            .await;
        assert_eq!(new_client.get_session_id(), session);
        assert_ne!(new_client.client_instance_id(), old_instance);

        assert!(
            repo.remove_client_instance_in_server("alpha", session, old_instance)
                .await
                .is_none()
        );
        let retained = repo
            .get_client_in_server("alpha", session)
            .await
            .expect("new client should survive stale close cleanup");
        assert_eq!(
            retained.client_instance_id(),
            new_client.client_instance_id()
        );

        assert!(
            repo.remove_client_instance_in_server(
                "alpha",
                session,
                new_client.client_instance_id()
            )
            .await
            .is_some()
        );
        assert!(repo.get_client_in_server("alpha", session).await.is_none());
    }

    #[tokio::test]
    async fn remote_epoch_fence_rejects_stale_ops_and_makes_same_epoch_reset_idempotent() {
        let repo = ClientRepository::new(1, 16);
        let session = ClientSessionIdentifier::new(2, 1).unwrap();

        repo.apply_remote_operation_with_epoch(10, remote_add_entry(2, 1, 1).await, 0)
            .await
            .unwrap();
        repo.reset_clients_from_node(2, 10).await;
        assert!(repo.get_client_in_server("alpha", session).await.is_some());

        repo.reset_clients_from_node(2, 9).await;
        assert!(repo.get_client_in_server("alpha", session).await.is_some());
        assert!(
            repo.apply_remote_operation_with_epoch(9, remote_add_entry(2, 2, 2).await, 0)
                .await
                .is_err()
        );
        assert!(
            repo.get_client_in_server("alpha", ClientSessionIdentifier::new(2, 2).unwrap())
                .await
                .is_none()
        );

        repo.apply_remote_operation_with_epoch(11, remote_add_entry(2, 1, 1).await, 0)
            .await
            .unwrap();
        assert_eq!(
            repo.known_remote_origin_versions().await.get(&2),
            Some(&(11, 1))
        );
    }

    #[tokio::test]
    async fn offline_same_epoch_retains_version_floor_until_snapshot_rebuilds_state() {
        let repo = ClientRepository::new(1, 16);
        repo.apply_remote_operation_with_epoch(10, remote_add_entry(2, 1, 1).await, 0)
            .await
            .unwrap();
        repo.remove_clients_from_node(2).await;

        assert!(
            repo.install_remote_client_snapshot(2, 10, 0, 0, Vec::new(), &HashMap::new())
                .await
                .is_err(),
            "an offline shard cannot regress within the same boot epoch"
        );
        assert_eq!(
            repo.install_remote_client_snapshot(
                2,
                10,
                1,
                1,
                vec![(*remote_add_entry(2, 1, 0).await).clone()],
                &HashMap::from([("alpha".to_owned(), 0)]),
            )
            .await
            .unwrap(),
            ClientSnapshotInstallOutcome::Installed
        );
        assert_eq!(
            repo.known_remote_origin_versions().await.get(&2),
            Some(&(10, 1))
        );
    }

    #[tokio::test]
    async fn owner_log_slice_detects_pruning_and_hides_snapshot_baseline() {
        let repo = ClientRepository::new(1, 2);
        for version in 1..=3 {
            repo.apply_remote_operation_with_epoch(
                7,
                remote_add_entry(2, version as u32, version).await,
                0,
            )
            .await
            .unwrap();
        }

        assert!(matches!(
            repo.get_log_slice_for_node(2, 0).await,
            ClientOriginLogSlice::TooOld
        ));
        assert!(matches!(
            repo.get_log_slice_for_node(2, 1).await,
            ClientOriginLogSlice::Available(entries)
                if entries.iter().map(|entry| entry.version).collect::<Vec<_>>() == vec![2, 3]
        ));

        let snapshot_entry = (*remote_add_entry(2, 9, 0).await).clone();
        assert_eq!(
            repo.install_remote_client_snapshot(
                2,
                7,
                5,
                5,
                vec![snapshot_entry],
                &HashMap::from([("alpha".to_owned(), 0)]),
            )
            .await
            .unwrap(),
            ClientSnapshotInstallOutcome::Installed
        );
        assert!(matches!(
            repo.get_log_slice_for_node(2, 4).await,
            ClientOriginLogSlice::TooOld
        ));
        assert!(matches!(
            repo.get_log_slice_for_node(2, 5).await,
            ClientOriginLogSlice::Available(entries) if entries.is_empty()
        ));
    }

    #[tokio::test]
    async fn snapshot_replacement_preserves_and_drains_newer_pending_suffix() {
        let repo = ClientRepository::new(1, 16);
        let pending_session = ClientSessionIdentifier::new(2, 3).unwrap();
        repo.apply_remote_operation_with_epoch(7, remote_add_entry(2, 3, 3).await, 0)
            .await
            .unwrap();
        assert!(
            repo.get_client_in_server("alpha", pending_session)
                .await
                .is_none()
        );

        let baseline = (*remote_add_entry(2, 1, 0).await).clone();
        assert_eq!(
            repo.install_remote_client_snapshot(
                2,
                7,
                2,
                2,
                vec![baseline],
                &HashMap::from([("alpha".to_owned(), 0)]),
            )
            .await
            .unwrap(),
            ClientSnapshotInstallOutcome::Installed
        );
        repo.drain_pending_ops("alpha", 0).await;
        assert!(
            repo.get_client_in_server("alpha", pending_session)
                .await
                .is_some()
        );
        assert_eq!(
            repo.known_remote_origin_versions().await.get(&2),
            Some(&(7, 3))
        );
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Apply a `ClientGlobalStateDelta` directly to a `ClientGlobalState`.
/// Used by `apply_remote_operation` to replay remote deltas.
pub(crate) fn apply_delta_to_global_state(
    gs: &mut crate::client::client_global_state::ClientGlobalState,
    delta: &crate::client::state_log::ClientGlobalStateDelta,
) {
    if let Some(v) = delta.current_channel_id {
        gs.set_current_channel_id(v);
    }
    if let Some(ref v) = delta.listening_channel_add {
        for ch in v {
            gs.listen_channel(*ch);
        }
    }
    if let Some(ref v) = delta.listening_channel_remove {
        for ch in v {
            gs.unlisten_channel(*ch);
        }
    }
    if let Some(v) = delta.mute {
        gs.set_mute(v);
    }
    if let Some(v) = delta.deaf {
        gs.set_deaf(v);
    }
    if let Some(v) = delta.self_mute {
        gs.set_self_mute(v);
    }
    if let Some(v) = delta.self_deaf {
        gs.set_self_deaf(v);
    }
    if let Some(v) = delta.priority_speaker {
        gs.set_priority_speaker(v);
    }
    if let Some(v) = delta.recording {
        gs.set_recording(v);
    }
    if let Some(ref v) = delta.plugin_context {
        gs.set_plugin_context(v.clone());
    }
    if let Some(ref v) = delta.plugin_identity {
        gs.set_plugin_identity(v.clone());
    }
    if let Some(ref v) = delta.texture_url {
        let hash = delta
            .texture_hash
            .as_ref()
            .cloned()
            .unwrap_or_else(|| gs.get_texture_hash().map(|s| s.to_owned()));
        gs.set_texture_blob(v.clone(), hash);
    } else if let Some(ref v) = delta.texture_hash {
        let url = delta
            .texture_url
            .as_ref()
            .cloned()
            .unwrap_or_else(|| gs.get_texture_url().map(|s| s.to_owned()));
        gs.set_texture_blob(url, v.clone());
    }
    if let Some(ref v) = delta.comment_url {
        let hash = delta
            .comment_hash
            .as_ref()
            .cloned()
            .unwrap_or_else(|| gs.get_comment_hash().map(|s| s.to_owned()));
        gs.set_comment_blob(v.clone(), hash);
    } else if let Some(ref v) = delta.comment_hash {
        let url = delta
            .comment_url
            .as_ref()
            .cloned()
            .unwrap_or_else(|| gs.get_comment_url().map(|s| s.to_owned()));
        gs.set_comment_blob(url, v.clone());
    }
    if let Some(ref v) = delta.user_id {
        gs.set_user_id(*v);
    }
    if let Some(ref v) = delta.fqdn {
        gs.set_fqdn(v.clone());
    }
    if let Some(ref v) = delta.groups {
        gs.set_groups(v.clone());
    }
    if let Some(v) = delta.is_superuser {
        gs.set_superuser(v);
    }
    if let Some(v) = delta.hidden_from_regular_users {
        gs.set_hidden_from_regular_users(v);
    }
    if let Some(v) = delta.suppress {
        gs.set_suppress(v);
    }
    if let Some(ref v) = delta.tokens {
        gs.set_tokens(v.clone());
    }
    if let Some(ref v) = delta.display_name {
        gs.set_display_name(v.clone());
    }
}

fn append_indexed_clients(
    clients_by_id: &HashMap<ScopedSessionId, Arc<Box<Client>>>,
    clients_by_channel: &HashMap<ScopedChannelId, HashSet<ScopedSessionId>>,
    listeners_by_channel: &HashMap<ScopedChannelId, HashSet<ScopedSessionId>>,
    server_id: &str,
    channel_ids: &HashSet<u32>,
    seen: &mut HashSet<ScopedSessionId>,
    out: &mut Vec<Arc<Box<Client>>>,
) {
    for &channel_id in channel_ids {
        let channel_key = ScopedChannelId::new(server_id.to_owned(), channel_id);
        for ids in [
            clients_by_channel.get(&channel_key),
            listeners_by_channel.get(&channel_key),
        ]
        .into_iter()
        .flatten()
        {
            for id in ids {
                if seen.insert(id.clone()) {
                    if let Some(client) = clients_by_id.get(id) {
                        out.push(Arc::clone(client));
                    }
                }
            }
        }
    }
}

fn is_own_replayed_add_client(
    op: &ClientStateOperation,
    session_id: ClientSessionIdentifier,
    client_instance_id: ClientInstanceId,
) -> bool {
    matches!(
        op,
        ClientStateOperation::AddClient {
            session_id: id,
            client_instance_id: instance_id,
            ..
        } if *id == session_id && *instance_id == client_instance_id
    )
}

fn projection_broadcast_capacity(log_max_entries: usize) -> usize {
    log_max_entries.saturating_mul(2).max(1024)
}

/// A snapshot `AddClient` for the viewer cannot be replayed as an add because
/// the connection already knows its own session. Convert it to an
/// authoritative full-state update instead, so values missed before the
/// snapshot floor (including false and cleared values) still reconcile the
/// connection's self view and trigger the normal home-channel/ACL refreshes.
fn authoritative_rebase_entry_for_viewer(
    entry: &mut ClientStateLogEntry,
    viewer_session_id: ClientSessionIdentifier,
    viewer_client_instance_id: ClientInstanceId,
) {
    let ClientStateOperation::AddClient {
        server_id,
        session_id,
        client_instance_id,
        initial_state,
        ..
    } = &entry.op
    else {
        return;
    };
    if *session_id != viewer_session_id || *client_instance_id != viewer_client_instance_id {
        return;
    }

    entry.op = ClientStateOperation::UpdateGlobalState {
        server_id: server_id.clone(),
        session_id: *session_id,
        client_instance_id: *client_instance_id,
        sender_session_id: None,
        delta: initial_state.clone(),
    };
}
