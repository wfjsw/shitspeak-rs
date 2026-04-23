use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::{
    client::{
        Client, client_session_identifier::ClientSessionIdentifier,
        state_log::{ClientStateBroadcastPayload, ClientStateLogEntry, ClientStateOperation},
    },
    constants::MAX_LOCAL_SESSION_ID,
};

/// Maximum number of log entries to retain in the in-memory ring buffer.
const LOG_MAX_ENTRIES: usize = 10_000;

pub struct ClientRepository {
    local_node_id: u16,

    /// All client state, the version counter, and the log ring buffer
    /// are protected by a single `RwLock` so that reads (lookups, log
    /// queries) don't contend with each other, but mutations are
    /// serialised.
    register: RwLock<ClientRegister>,

    clients_by_host: RwLock<HashMap<IpAddr, HashSet<ClientSessionIdentifier>>>,
    clients_by_udp_address: RwLock<HashMap<SocketAddr, ClientSessionIdentifier>>,

    // The pointer only store local_session_id part
    allocation_pointer: Mutex<u32>,
    free_ids: Mutex<HashSet<u32>>,

    /// Broadcast channel for per-client subscribers and future S2S peers.
    tx: broadcast::Sender<Arc<ClientStateBroadcastPayload>>,
}

pub struct ClientRegister {
    // ── Local state ────────────────────────────────────────────────────
    /// Clients homed on this node.
    local_clients: HashMap<ClientSessionIdentifier, Arc<Box<Client>>>,
    /// Ring buffer of local log entries.
    local_log: VecDeque<Arc<ClientStateLogEntry>>,

    // ── Remote state (per peer node) ────────────────────────────────────
    /// Remote clients, keyed by node_id then session identifier.
    remote_clients: HashMap<u16, HashMap<ClientSessionIdentifier, Arc<Box<Client>>>>,
    /// Ring buffer per remote node.
    remote_logs: HashMap<u16, VecDeque<Arc<ClientStateLogEntry>>>,

    // ── Unified version vector ──────────────────────────────────────────
    /// Monotonic version counter per node (local + all remotes).
    /// The local node's version is stored under `local_node_id`.
    versions: HashMap<u16, u64>,
}

impl ClientRegister {
    /// Look up a client in either local or remote maps.
    fn get(&self, id: &ClientSessionIdentifier) -> Option<&Arc<Box<Client>>> {
        if id.node_id == 0 {
            // FIXME: node_id 0 is ambiguous — need local_node_id context.
            // For now, fall through to local then remote.
            self.local_clients.get(id)
                .or_else(|| self.remote_clients.values().find_map(|m| m.get(id)))
        } else {
            self.local_clients.get(id)
                .or_else(|| self.remote_clients.get(&id.node_id).and_then(|m| m.get(id)))
        }
    }

    /// Iterate over all clients (local + remote).
    fn all_clients(&self) -> impl Iterator<Item = &Arc<Box<Client>>> {
        self.local_clients.values()
            .chain(self.remote_clients.values().flat_map(|m| m.values()))
    }

    /// Iterate over all client entries (local + remote).
    fn all_entries(&self) -> impl Iterator<Item = (&ClientSessionIdentifier, &Arc<Box<Client>>)> {
        self.local_clients.iter()
            .chain(self.remote_clients.values().flat_map(|m| m.iter()))
            .map(|(k, v)| (k, v))
    }
}

impl ClientRepository {
    pub fn new(local_node_id: u16) -> Self {
        let (tx, _) = broadcast::channel(1024);
        ClientRepository {
            local_node_id,
            register: RwLock::new(ClientRegister {
                local_clients: HashMap::new(),
                local_log: VecDeque::new(),
                remote_clients: HashMap::new(),
                remote_logs: HashMap::new(),
                versions: HashMap::new(),
            }),
            clients_by_host: RwLock::new(HashMap::new()),
            clients_by_udp_address: RwLock::new(HashMap::new()),
            allocation_pointer: Mutex::new(0),
            free_ids: Mutex::new(HashSet::new()),
            tx,
        }
    }

    /// The node ID of this repository.
    pub fn local_node_id(&self) -> u16 {
        self.local_node_id
    }

    pub async fn allocate_local_client(
        &self,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
    ) -> Arc<Box<Client>> {
        let mut register = self.register.write().await;
        let mut client_by_udp_address_guard = self.clients_by_udp_address.write().await;
        let mut client_by_host_guard = self.clients_by_host.write().await;
        let mut free_ids_guard = self.free_ids.lock().await;

        let id = {
            if let Some(free_id) = free_ids_guard.iter().next().copied() {
                free_ids_guard.remove(&free_id);
                free_id
            } else {
                let mut allocation_pointer = self.allocation_pointer.lock().await;
                let id = *allocation_pointer;

                if id > MAX_LOCAL_SESSION_ID {
                    panic!("Exceeded maximum number of local session IDs. Consider rearranging the allocation strategy");
                }

                *allocation_pointer += 1;
                id
            }
        };
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let client = Client::new_local(
            client_identifier,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
        );
        
        let client = Arc::new(client);

        register.local_clients.insert(client_identifier, Arc::clone(&client));

        if let Some(udp_address) = udp_address {
            client_by_udp_address_guard
                .insert(udp_address, client_identifier);
        }

        if let Some(set) = client_by_host_guard.get_mut(&tcp_address.ip()) {
            set.insert(client_identifier);
        } else {
            let mut set = HashSet::new();
            set.insert(client_identifier);
            client_by_host_guard.insert(tcp_address.ip(), set);
        }

        // NOTE: AddClient log entry is deferred until the client
        // authenticates.  See `publish_client()`.

        client
    }

    /// Emit the `AddClient` log entry for a client that has completed
    /// authentication.  Sets the `published` flag so that future
    /// `remove_client` calls will emit a corresponding `RemoveClient`.
    pub async fn publish_client(&self, id: ClientSessionIdentifier) {
        let client = match self.register.read().await.local_clients.get(&id).cloned() {
            Some(c) => c,
            None => return,
        };

        client.set_published(true);

        self.commit_operation(ClientStateOperation::AddClient {
            session_id: id,
            real_ip: client.get_real_ip_address(),
            tcp_addr: client.get_tcp_address(),
            udp_addr: client.get_udp_address(),
            local_addr: client.get_tcp_address(),
            cert_hash: client.get_certificate_hash().map(|h| h.to_vec()),
            login_time: client.get_login_time(),
        }).await;
    }

    pub async fn add_remote_client(&self, id: ClientSessionIdentifier, client: Arc<Box<Client>>) {
        let node_id = client.get_node_id();
        if node_id == self.local_node_id {
            panic!("Not supposed to add a remote client with the local node ID");
        }

        // Snapshot fields before moving into the map
        let real_ip = client.get_real_ip_address();
        let tcp_addr = client.get_tcp_address();
        let udp_addr = client.get_udp_address();
        let cert_hash = client.get_certificate_hash().map(|h| h.to_vec());
        let login_time = client.get_login_time();

        {
            let mut register = self.register.write().await;
            register.remote_clients
                .entry(node_id)
                .or_default()
                .insert(id, client);
            // Ensure version/log entries exist for this node
            register.versions.entry(node_id).or_insert(0);
            register.remote_logs.entry(node_id).or_default();
        }

        // ── Log the operation ───────────────────────────────────────────
        self.commit_operation(ClientStateOperation::AddClient {
            session_id: id,
            real_ip,
            tcp_addr,
            udp_addr,
            local_addr: tcp_addr, // remote clients don't have a separate local addr
            cert_hash,
            login_time,
        }).await;
    }

    pub async fn remove_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        let mut register = self.register.write().await;
        let mut client_by_udp_address_guard = self.clients_by_udp_address.write().await;
        let mut client_by_host_guard = self.clients_by_host.write().await;
        let mut free_ids_guard = self.free_ids.lock().await;

        // Try local first, then remote
        let client = if let Some(c) = register.local_clients.remove(&id) {
            c
        } else if let Some(remote_map) = register.remote_clients.get_mut(&id.node_id) {
            match remote_map.remove(&id) {
                Some(c) => {
                    // Clean up empty remote node entries
                    if remote_map.is_empty() {
                        register.remote_clients.remove(&id.node_id);
                        register.versions.remove(&id.node_id);
                        register.remote_logs.remove(&id.node_id);
                    }
                    c
                }
                None => return None,
            }
        } else {
            return None;
        };

        if client.get_node_id() == self.local_node_id {
            if let Some(udp_address) = client.get_udp_address() {
                client_by_udp_address_guard.remove(&udp_address);
            }

            let tcp_address = client.get_tcp_address();

            if let Some(set) = client_by_host_guard.get_mut(&tcp_address.ip()) {
                set.remove(&id);
                if set.is_empty() {
                    client_by_host_guard.remove(&tcp_address.ip());
                }
            }

            free_ids_guard.insert(id.local_session_id);
        }

        // ── Log the operation (only if client was published) ────────
        let was_published = client.is_published();
        drop(register);
        drop(client_by_udp_address_guard);
        drop(client_by_host_guard);
        drop(free_ids_guard);

        if was_published {
            self.commit_operation(ClientStateOperation::RemoveClient {
                session_id: id,
            }).await;
        }

        Some(client)
    }

    pub async fn clear_clients_from_node(&self, node_id: u16) {
        if node_id == self.local_node_id {
            panic!("Not supposed to clear clients from the local node");
        }

        let mut register = self.register.write().await;
        let mut free_ids = self.free_ids.lock().await;

        // Collect published status before removing from map
        let (ids_to_remove, published): (Vec<ClientSessionIdentifier>, Vec<bool>) = match register.remote_clients.get(&node_id) {
            Some(remote_map) => {
                let ids: Vec<ClientSessionIdentifier> = remote_map.keys().copied().collect();
                let pub_flags: Vec<bool> = ids.iter()
                    .filter_map(|id| remote_map.get(id))
                    .map(|c| c.is_published())
                    .collect();
                (ids, pub_flags)
            }
            None => return,
        };

        // Remove the entire remote node entry
        register.remote_clients.remove(&node_id);
        register.versions.remove(&node_id);
        register.remote_logs.remove(&node_id);
        drop(register);
        drop(free_ids);

        // ── Log each removal (only if client was published) ─────────────
        for (id, was_published) in ids_to_remove.iter().zip(published.iter()) {
            if *was_published {
                self.commit_operation(ClientStateOperation::RemoveClient {
                    session_id: *id,
                }).await;
            }
        }
    }

    pub async fn get_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        self.register.read().await.get(&id).cloned()
    }

    /// Look up a client by their UDP socket address.
    pub async fn get_client_by_udp_address(&self, addr: &SocketAddr) -> Option<Arc<Box<Client>>> {
        let by_udp = self.clients_by_udp_address.read().await;
        let id = by_udp.get(addr)?;
        self.register.read().await.get(id).cloned()
    }

    /// Look up clients sharing the same IP (for UDP packet matching fallback).
    pub async fn get_clients_by_ip(&self, ip: &IpAddr) -> Vec<Arc<Box<Client>>> {
        let by_host = self.clients_by_host.read().await;
        let register = self.register.read().await;
        match by_host.get(ip) {
            Some(ids) => ids.iter().filter_map(|id| register.get(id).cloned()).collect(),
            None => Vec::new(),
        }
    }

    // ── Broadcast helpers ─────────────────────────────────────────────────

    /// Send `message` to every connected client.
    pub async fn broadcast_all(&self, message: &crate::messages::Message) {
        let register = self.register.read().await;
        for client in register.all_clients() {
            if let Err(e) = client.write_proto_message(message).await {
                tracing::warn!("broadcast_all write error: {e}");
            }
        }
    }

    /// Send `message` to every client except `exclude`.
    pub async fn broadcast_except(
        &self,
        exclude: ClientSessionIdentifier,
        message: &crate::messages::Message,
    ) {
        let register = self.register.read().await;
        for (id, client) in register.all_entries() {
            if *id == exclude {
                continue;
            }
            if let Err(e) = client.write_proto_message(message).await {
                tracing::warn!("broadcast_except write error: {e}");
            }
        }
    }

    /// Send a batch of messages to every client except `exclude`, using a
    /// single write per client.
    pub async fn broadcast_batch_except(
        &self,
        exclude: ClientSessionIdentifier,
        messages: &[crate::messages::Message],
    ) {
        let register = self.register.read().await;
        for (id, client) in register.all_entries() {
            if *id == exclude {
                continue;
            }
            if let Err(e) = client.write_proto_message_batch(messages).await {
                tracing::warn!("broadcast_batch_except write error: {e}");
            }
        }
    }

    /// Return a snapshot of all currently-connected clients (including unauthenticated).
    pub async fn get_all_clients(&self) -> Vec<Arc<Box<Client>>> {
        self.register.read().await.all_clients().cloned().collect()
    }

    pub async fn len(&self) -> usize {
        let register = self.register.read().await;
        register.local_clients.len() + register.remote_clients.values().map(|m| m.len()).sum::<usize>()
    }

    /// Return a snapshot of all clients along with the current version
    /// for every known node (local + remote).
    ///
    /// Returns `(clients, versions)` where `versions` maps `node_id → version`.
    pub async fn snapshot_with_versions(&self) -> (Vec<Arc<Box<Client>>>, HashMap<u16, u64>) {
        let register = self.register.read().await;
        let clients: Vec<_> = register.all_clients().cloned().collect();
        (clients, register.versions.clone())
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
    ) -> Result<(Vec<crate::messages::Message>, HashMap<u16, u64>), ()> {
        let register = self.register.read().await;

        // Check that no log has been pruned past the requested version
        let local_since = last_seen.get(&self.local_node_id).copied().unwrap_or(0);
        if local_since > 0 {
            match register.local_log.front() {
                Some(oldest) if oldest.version > local_since => {
                    tracing::error!(
                        "Local log pruned past requested version: oldest={} requested={}",
                        oldest.version, local_since,
                    );
                    return Err(());
                }
                _ => {}
            }
        }
        for (node_id, log) in &register.remote_logs {
            let since = last_seen.get(node_id).copied().unwrap_or(0);
            if since > 0 {
                if let Some(oldest) = log.front() {
                    if oldest.version > since {
                        tracing::error!(
                            "Remote log for node {} pruned past requested version: oldest={} requested={}",
                            node_id, oldest.version, since,
                        );
                        return Err(());
                    }
                }
            }
        }

        // Collect all qualifying entries from every log
        let mut entries: Vec<&Arc<ClientStateLogEntry>> = Vec::new();

        for entry in &register.local_log {
            if entry.version > local_since {
                entries.push(entry);
            }
        }

        for (node_id, log) in &register.remote_logs {
            let since = last_seen.get(node_id).copied().unwrap_or(0);
            for entry in log {
                if entry.version > since {
                    entries.push(entry);
                }
            }
        }

        // Sort by timestamp, then version for deterministic ordering
        entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.version.cmp(&b.version))
        });

        // Track the max version seen per node
        let mut new_versions: HashMap<u16, u64> = HashMap::new();

        // Convert to messages
        let mut messages = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(msg) = entry.to_message(self).await {
                messages.push(msg);
            }
            let cur = new_versions.entry(entry.node_id).or_insert(0);
            *cur = (*cur).max(entry.version);
        }

        Ok((messages, new_versions))
    }

    /// Send `message` to a single client identified by `id`.
    /// Returns `true` if the client was found and the write succeeded.
    pub async fn send_to(
        &self,
        id: ClientSessionIdentifier,
        message: &crate::messages::Message,
    ) -> bool {
        let client = {
            let register = self.register.read().await;
            register.get(&id).cloned()
        };
        match client {
            Some(c) => {
                if let Err(e) = c.write_proto_message(message).await {
                    tracing::warn!("send_to {id:?} write error: {e}");
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
        self.register.try_read()
            .map(|r| r.versions.get(&self.local_node_id).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// Subscribe to the stream of committed `ClientStateLogEntry`s.
    /// Used by per-client TCP loops and future S2S replication.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<ClientStateBroadcastPayload>> {
        self.tx.subscribe()
    }

    /// Return all local log entries with `version > since_version`.
    pub async fn get_log_since(&self, since_version: u64) -> Vec<Arc<ClientStateLogEntry>> {
        self.register
            .read()
            .await
            .local_log
            .iter()
            .filter(|op| op.version > since_version)
            .cloned()
            .collect()
    }

    /// Apply an operation that arrived from a remote node.
    ///
    /// The operation is applied to the local in-memory map but **not**
    /// re-appended to the log or re-broadcast (the remote node already did
    /// that).  Idempotent: if `op.version ≤ current_version` the op is
    /// silently dropped.
    pub async fn apply_remote_operation(
        &self,
        op: Arc<ClientStateLogEntry>,
    ) -> Result<(), ()> {
        let mut register = self.register.write().await;
        let remote_node = op.node_id;

        // Check version against the remote node's tracked version
        let current_ver = register.versions.get(&remote_node).copied().unwrap_or(0);
        if op.version <= current_ver {
            return Ok(());
        }

        match &op.op {
            ClientStateOperation::AddClient { session_id, .. } => {
                // Remote add — we don't have the actual Client object yet.
                // This is a stub; full S2S will construct a remote Client.
                tracing::debug!("remote AddClient {session_id:?} v{}", op.version);
            }
            ClientStateOperation::RemoveClient { session_id } => {
                if let Some(remote_map) = register.remote_clients.get_mut(&remote_node) {
                    remote_map.remove(session_id);
                    if remote_map.is_empty() {
                        register.remote_clients.remove(&remote_node);
                        register.versions.remove(&remote_node);
                        register.remote_logs.remove(&remote_node);
                    }
                }
            }
            ClientStateOperation::UpdateGlobalState {
                session_id,
                sender_session_id: _,
                delta,
            } => {
                let client = register.get(session_id).cloned();
                if let Some(client) = client {
                    let mut gs = client.write_global_state_direct().await;
                    apply_delta_to_global_state(&mut gs, delta);
                }
            }
        }

        register.versions.insert(remote_node, op.version);
        Ok(())
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Create a new log entry and commit it: bump version, push to ring
    /// buffer, broadcast to subscribers, trim old entries.
    ///
    /// Acquires the register write lock internally.
    pub(crate) async fn commit_operation(&self, op: ClientStateOperation) {
        self.commit_operation_sync(op);
    }

    /// Synchronous version of `commit_operation`.  Safe to call from
    /// `Drop` impls (uses `try_write`).
    pub(crate) fn commit_operation_sync(&self, op: ClientStateOperation) {
        let broadcast = {
            let mut register = match self.register.try_write() {
                Ok(r) => r,
                Err(_) => return, // deadlock avoidance in Drop contexts
            };

            let cur = register.versions.entry(self.local_node_id).or_insert(0);
            *cur += 1;
            let version = *cur;
            debug_assert!(
                version < u64::MAX - 1_000_000,
                "ClientRepository version counter approaching u64::MAX — likely a bug"
            );

            let entry = Arc::new(ClientStateLogEntry {
                version,
                node_id: self.local_node_id,
                timestamp: chrono::Utc::now().timestamp_millis(),
                op,
            });

            register.local_log.push_back(Arc::clone(&entry));
            while register.local_log.len() > LOG_MAX_ENTRIES {
                register.local_log.pop_front();
            }

            // Build version vector
            let versions = register.versions.clone();

            Arc::new(ClientStateBroadcastPayload { entry, versions })
        };

        // Broadcast to subscribers (ignore NoSubscribers / Full errors)
        let _ = self.tx.send(broadcast);
    }

}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Apply a `ClientGlobalStateDelta` directly to a `ClientGlobalState`.
/// Used by `apply_remote_operation` to replay remote deltas.
pub(crate) fn apply_delta_to_global_state(
    gs: &mut crate::client::client_global_state::ClientGlobalState,
    delta: &crate::client::state_log::ClientGlobalStateDelta,
) {
    if let Some(ref v) = delta.protocol_version {
        gs.set_protocol_version(v.clone());
    }
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
    if let Some(v) = delta.suppress {
        gs.set_suppress(v);
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
        let hash = delta.texture_hash.as_ref().cloned().unwrap_or_else(|| {
            gs.get_texture_hash().map(|s| s.to_owned())
        });
        gs.set_texture_blob(v.clone(), hash);
    } else if let Some(ref v) = delta.texture_hash {
        let url = delta.texture_url.as_ref().cloned().unwrap_or_else(|| {
            gs.get_texture_url().map(|s| s.to_owned())
        });
        gs.set_texture_blob(url, v.clone());
    }
    if let Some(ref v) = delta.comment_url {
        let hash = delta.comment_hash.as_ref().cloned().unwrap_or_else(|| {
            gs.get_comment_hash().map(|s| s.to_owned())
        });
        gs.set_comment_blob(v.clone(), hash);
    } else if let Some(ref v) = delta.comment_hash {
        let url = delta.comment_url.as_ref().cloned().unwrap_or_else(|| {
            gs.get_comment_url().map(|s| s.to_owned())
        });
        gs.set_comment_blob(url, v.clone());
    }
    if let Some(ref v) = delta.user_id {
        gs.set_user_id(*v);
    }
    if let Some(ref v) = delta.groups {
        gs.set_groups(v.clone());
    }
    if let Some(ref v) = delta.tokens {
        gs.set_tokens(v.clone());
    }
    if let Some(ref v) = delta.display_name {
        gs.set_display_name(v.clone());
    }
}
