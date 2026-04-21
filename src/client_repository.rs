use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::{
    client::{
        Client, client_session_identifier::ClientSessionIdentifier,
        state_log::{ClientStateLogEntry, ClientStateOperation},
    },
    constants::MAX_LOCAL_SESSION_ID,
};

/// Maximum number of log entries to retain in the in-memory ring buffer.
const LOG_MAX_ENTRIES: usize = 10_000;

pub struct ClientRepository {
    local_node_id: u16,
    clients: RwLock<HashMap<ClientSessionIdentifier, Arc<Box<Client>>>>,

    clients_by_host: RwLock<HashMap<IpAddr, HashSet<ClientSessionIdentifier>>>,
    clients_by_udp_address: RwLock<HashMap<SocketAddr, ClientSessionIdentifier>>,

    // The pointer only store local_session_id part
    allocation_pointer: Mutex<u32>,
    free_ids: Mutex<HashSet<u32>>,

    // ── Versioned state log ─────────────────────────────────────────────
    /// Monotonic global version counter.  Incremented on every client
    /// add/remove and every `ClientGlobalState` mutation.
    version: AtomicU64,
    /// In-memory ring buffer of committed log entries.
    log: RwLock<VecDeque<Arc<ClientStateLogEntry>>>,
    /// Broadcast channel for per-client subscribers and future S2S peers.
    tx: broadcast::Sender<Arc<ClientStateLogEntry>>,
}

impl ClientRepository {
    pub fn new(local_node_id: u16) -> Self {
        let (tx, _) = broadcast::channel(1024);
        ClientRepository {
            local_node_id,
            clients: RwLock::new(HashMap::new()),
            clients_by_host: RwLock::new(HashMap::new()),
            clients_by_udp_address: RwLock::new(HashMap::new()),
            allocation_pointer: Mutex::new(0),
            free_ids: Mutex::new(HashSet::new()),
            version: AtomicU64::new(0),
            log: RwLock::new(VecDeque::new()),
            tx,
        }
    }

    pub async fn allocate_local_client(
        &self,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
    ) -> Arc<Box<Client>> {
        let mut clients_guard = self.clients.write().await;
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

        clients_guard.insert(client_identifier, Arc::clone(&client));

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
        let client = match self.clients.read().await.get(&id).cloned() {
            Some(c) => c,
            None => return,
        };

        client.set_published(true);

        let entry = self.make_entry(ClientStateOperation::AddClient {
            session_id: id,
            real_ip: client.get_real_ip_address(),
            tcp_addr: client.get_tcp_address(),
            udp_addr: client.get_udp_address(),
            local_addr: client.get_tcp_address(),
            cert_hash: client.get_certificate_hash().map(|h| h.to_vec()),
            login_time: client.get_login_time(),
        });
        self.commit(entry).await;
    }

    pub async fn add_remote_client(&self, id: ClientSessionIdentifier, client: Arc<Box<Client>>) {
        if client.get_node_id() == self.local_node_id {
            panic!("Not supposed to add a remote client with the local node ID");
        }

        // Snapshot fields before moving into the map
        let real_ip = client.get_real_ip_address();
        let tcp_addr = client.get_tcp_address();
        let udp_addr = client.get_udp_address();
        let cert_hash = client.get_certificate_hash().map(|h| h.to_vec());
        let login_time = client.get_login_time();

        self.clients.write().await.insert(id, client);

        // ── Log the operation ───────────────────────────────────────────
        let entry = self.make_entry(ClientStateOperation::AddClient {
            session_id: id,
            real_ip,
            tcp_addr,
            udp_addr,
            local_addr: tcp_addr, // remote clients don't have a separate local addr
            cert_hash,
            login_time,
        });
        self.commit(entry).await;
    }

    pub async fn remove_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        let mut clients_guard = self.clients.write().await;
        let mut client_by_udp_address_guard = self.clients_by_udp_address.write().await;
        let mut client_by_host_guard = self.clients_by_host.write().await;
        let mut free_ids_guard = self.free_ids.lock().await;

        if let Some(client) = clients_guard.remove(&id) {
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
            drop(clients_guard);
            drop(client_by_udp_address_guard);
            drop(client_by_host_guard);
            drop(free_ids_guard);

            if was_published {
                let entry = self.make_entry(ClientStateOperation::RemoveClient {
                    session_id: id,
                });
                self.commit(entry).await;
            }

            Some(client)
        } else {
            None
        }
    }

    pub async fn clear_clients_from_node(&self, node_id: u16) {
        if node_id == self.local_node_id {
            panic!("Not supposed to clear clients from the local node");
        }

        let mut clients = self.clients.write().await;
        let mut free_ids = self.free_ids.lock().await;

        let ids_to_remove: Vec<ClientSessionIdentifier> = clients
            .keys()
            .filter(|id| id.node_id == node_id)
            .copied()
            .collect();

        // Collect published status before removing from map
        let published: Vec<bool> = ids_to_remove
            .iter()
            .filter_map(|id| clients.get(id))
            .map(|c| c.is_published())
            .collect();

        for id in &ids_to_remove {
            clients.remove(id);
            free_ids.insert(id.get_local_session_id());
        }
        drop(clients);
        drop(free_ids);

        // ── Log each removal (only if client was published) ─────────────
        for (id, was_published) in ids_to_remove.iter().zip(published.iter()) {
            if *was_published {
                let entry = self.make_entry(ClientStateOperation::RemoveClient {
                    session_id: *id,
                });
                self.commit(entry).await;
            }
        }
    }

    pub async fn get_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        self.clients.read().await.get(&id).cloned()
    }

    /// Look up a client by their UDP socket address.
    pub async fn get_client_by_udp_address(&self, addr: &SocketAddr) -> Option<Arc<Box<Client>>> {
        let by_udp = self.clients_by_udp_address.read().await;
        let id = by_udp.get(addr)?;
        self.clients.read().await.get(id).cloned()
    }

    /// Look up clients sharing the same IP (for UDP packet matching fallback).
    pub async fn get_clients_by_ip(&self, ip: &IpAddr) -> Vec<Arc<Box<Client>>> {
        let by_host = self.clients_by_host.read().await;
        let clients = self.clients.read().await;
        match by_host.get(ip) {
            Some(ids) => ids.iter().filter_map(|id| clients.get(id).cloned()).collect(),
            None => Vec::new(),
        }
    }

    // ── Broadcast helpers ─────────────────────────────────────────────────

    /// Send `message` to every connected client.
    pub async fn broadcast_all(&self, message: &crate::messages::Message) {
        let clients = self.clients.read().await;
        for client in clients.values() {
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
        let clients = self.clients.read().await;
        for (id, client) in clients.iter() {
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
        let clients = self.clients.read().await;
        for (id, client) in clients.iter() {
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
        self.clients.read().await.values().cloned().collect()
    }

    /// Send `message` to a single client identified by `id`.
    /// Returns `true` if the client was found and the write succeeded.
    pub async fn send_to(
        &self,
        id: ClientSessionIdentifier,
        message: &crate::messages::Message,
    ) -> bool {
        let client = {
            let clients = self.clients.read().await;
            clients.get(&id).cloned()
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

    /// Return the current global version.
    pub fn current_version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Subscribe to the stream of committed `ClientStateLogEntry`s.
    /// Used by per-client TCP loops and future S2S replication.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<ClientStateLogEntry>> {
        self.tx.subscribe()
    }

    /// Return all log entries with `version > since_version`.
    pub async fn get_log_since(&self, since_version: u64) -> Vec<Arc<ClientStateLogEntry>> {
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
    /// re-appended to the log or re-broadcast (the remote node already did
    /// that).  Idempotent: if `op.version ≤ current_version` the op is
    /// silently dropped.
    pub async fn apply_remote_operation(
        &self,
        op: Arc<ClientStateLogEntry>,
    ) -> Result<(), ()> {
        let current = self.version.load(Ordering::Acquire);
        if op.version <= current {
            return Ok(());
        }

        match &op.op {
            ClientStateOperation::AddClient { session_id, .. } => {
                // Remote add — we don't have the actual Client object yet.
                // This is a stub; full S2S will construct a remote Client.
                tracing::debug!("remote AddClient {session_id:?} v{}", op.version);
            }
            ClientStateOperation::RemoveClient { session_id } => {
                let mut clients = self.clients.write().await;
                clients.remove(session_id);
            }
            ClientStateOperation::UpdateGlobalState { session_id, delta } => {
                let clients = self.clients.read().await;
                if let Some(client) = clients.get(session_id) {
                    let mut gs = client.write_global_state_direct().await;
                    apply_delta_to_global_state(&mut gs, delta);
                }
            }
        }

        self.version.fetch_max(op.version, Ordering::AcqRel);
        Ok(())
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Create a new log entry, bumping the global version.
    pub(crate) fn make_entry(&self, op: ClientStateOperation) -> ClientStateLogEntry {
        let version = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        // Safety net: in debug builds, panic if we're within 1M of wrapping.
        // In practice u64 will never wrap (584K years at 1M ops/s), but a
        // tight mutation-loop bug could burn through versions in testing.
        debug_assert!(
            version < u64::MAX - 1_000_000,
            "ClientRepository version counter approaching u64::MAX — likely a bug"
        );
        ClientStateLogEntry {
            version,
            node_id: self.local_node_id,
            timestamp: chrono::Utc::now().timestamp(),
            op,
        }
    }

    /// Commit a log entry: push to ring buffer, broadcast to subscribers,
    /// trim old entries.
    ///
    /// This is a synchronous operation (in-memory only).  The `async` signature
    /// exists for API consistency and future disk-backed persistence.
    pub(crate) async fn commit(&self, entry: ClientStateLogEntry) {
        self.commit_sync(entry);
    }

    /// Synchronous version of `commit`.  Safe to call from `Drop` impls.
    pub(crate) fn commit_sync(&self, entry: ClientStateLogEntry) {
        let entry = Arc::new(entry);

        // Push to ring buffer (use try_write to avoid deadlock in Drop contexts)
        if let Ok(mut log) = self.log.try_write() {
            log.push_back(Arc::clone(&entry));
            while log.len() > LOG_MAX_ENTRIES {
                log.pop_front();
            }
        }

        // Broadcast to subscribers (ignore NoSubscribers / Full errors)
        let _ = self.tx.send(entry);
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
    if let Some(ref v) = delta.listening_channel_id {
        // Rebuild listening set: clear and re-add
        let current: Vec<u32> = gs.get_listening_channel_id().iter().copied().collect();
        for ch in &current {
            gs.unlisten_channel(*ch);
        }
        for ch in v {
            gs.listen_channel(*ch);
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
