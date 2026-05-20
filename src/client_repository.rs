use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, RwLock as AsyncRwLock};
use tokio_rustls::server::TlsStream;

use crate::{
    client::{
        client_session_identifier::ClientSessionIdentifier,
        state_log::{
            ClientGlobalStateDelta, ClientStateBroadcastPayload, ClientStateLogEntry,
            ClientStateOperation,
        },
        Client,
    },
    constants::MAX_LOCAL_SESSION_ID,
    types::{default_server_id, ScopedChannelId, ScopedSessionId, DEFAULT_SERVER_ID},
};

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

    /// All client state, the version counter, and the log ring buffer
    /// are protected by a single `RwLock` so that reads (lookups, log
    /// queries) don't contend with each other, but mutations are
    /// serialised.
    register: AsyncRwLock<ClientRegister>,

    clients_by_host: ParkingRwLock<HashMap<IpAddr, HashSet<ScopedSessionId>>>,
    clients_by_udp_address: ParkingRwLock<HashMap<UdpBindingKey, ScopedSessionId>>,

    // These pools store only the local_session_id part, independently per server_id.
    allocation_pointers: ParkingMutex<HashMap<String, u32>>,
    free_ids: ParkingMutex<HashMap<String, HashSet<u32>>>,

    /// Broadcast channel for per-client subscribers and future S2S peers.
    tx: broadcast::Sender<Arc<ClientStateBroadcastPayload>>,
}

pub struct ClientRegister {
    // ── Local state ────────────────────────────────────────────────────
    /// Clients homed on this node.
    local_clients: HashMap<ScopedSessionId, Arc<Box<Client>>>,
    /// Ring buffer of local log entries.
    local_log: VecDeque<Arc<ClientStateLogEntry>>,

    // ── Remote state (per peer node) ────────────────────────────────────
    /// Remote clients, keyed by node_id then session identifier.
    remote_clients: HashMap<u16, HashMap<ScopedSessionId, Arc<Box<Client>>>>,
    /// Ring buffer per remote node.
    remote_logs: HashMap<u16, VecDeque<Arc<ClientStateLogEntry>>>,

    // ── Unified version vector ──────────────────────────────────────────
    /// Monotonic version counter per node (local + all remotes).
    /// The local node's version is stored under `local_node_id`.
    versions: HashMap<u16, u64>,

    // ── Causal consistency ─────────────────────────────────────────────
    /// Remote client log entries waiting for channel state to catch up.
    /// Entries remain in remote-log version order; each stores its server-scoped effective dep.
    pending_remote_ops: VecDeque<(Arc<ClientStateLogEntry>, u64)>,
    /// Last pending effective dependency per server scope.
    last_pending_effective_dep_by_server: HashMap<String, u64>,
    /// Latest known channel version per server scope, used to release pending ops in order.
    pending_channel_versions: HashMap<String, u64>,

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

impl ClientRegister {
    /// Look up a client in the local or owning remote map.
    fn get(&self, id: &ScopedSessionId, local_node_id: u16) -> Option<&Arc<Box<Client>>> {
        if id.session_id().node_id == local_node_id {
            self.local_clients.get(id)
        } else {
            self.remote_clients
                .get(&id.session_id().node_id)
                .and_then(|m| m.get(id))
        }
    }

    /// Iterate over locally connected clients.
    fn local_clients(&self) -> impl Iterator<Item = &Arc<Box<Client>>> {
        self.local_clients.values()
    }

    /// Iterate over all clients (local + remote).
    fn all_clients(&self) -> impl Iterator<Item = &Arc<Box<Client>>> {
        self.local_clients
            .values()
            .chain(self.remote_clients.values().flat_map(|m| m.values()))
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

    /// Iterate over all client entries (local + remote).
    fn all_entries(&self) -> impl Iterator<Item = (&ScopedSessionId, &Arc<Box<Client>>)> {
        self.local_clients
            .iter()
            .chain(self.remote_clients.values().flat_map(|m| m.iter()))
            .map(|(k, v)| (k, v))
    }
}

impl ClientRepository {
    pub fn new(local_node_id: u16, log_max_entries: usize) -> Self {
        let (tx, _) = broadcast::channel(1024);
        ClientRepository {
            local_node_id,
            log_max_entries: log_max_entries.max(1),
            register: AsyncRwLock::new(ClientRegister {
                local_clients: HashMap::new(),
                local_log: VecDeque::new(),
                remote_clients: HashMap::new(),
                remote_logs: HashMap::new(),
                versions: HashMap::new(),
                pending_remote_ops: VecDeque::new(),
                last_pending_effective_dep_by_server: HashMap::new(),
                pending_channel_versions: HashMap::new(),
                clients_by_channel: HashMap::new(),
                client_channel: HashMap::new(),
                listeners_by_channel: HashMap::new(),
            }),
            clients_by_host: ParkingRwLock::new(HashMap::new()),
            clients_by_udp_address: ParkingRwLock::new(HashMap::new()),
            allocation_pointers: ParkingMutex::new(HashMap::new()),
            free_ids: ParkingMutex::new(HashMap::new()),
            tx,
        }
    }

    /// The node ID of this repository.
    pub fn local_node_id(&self) -> u16 {
        self.local_node_id
    }

    fn allocate_local_session_id(&self, server_id: &str) -> u32 {
        let mut free_ids_guard = self.free_ids.lock();
        if let Some(free_ids) = free_ids_guard.get_mut(server_id) {
            if let Some(free_id) = free_ids.iter().next().copied() {
                free_ids.remove(&free_id);
                return free_id;
            }
        }
        drop(free_ids_guard);

        let mut pointers = self.allocation_pointers.lock();
        let allocation_pointer = pointers.entry(server_id.to_owned()).or_insert(0);
        let id = *allocation_pointer;

        if id > MAX_LOCAL_SESSION_ID {
            panic!("Exceeded maximum number of local session IDs for server_id={server_id}. Consider rearranging the allocation strategy");
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
        let new_local_id = self.allocate_local_session_id(new_server_id);
        let new_id = ClientSessionIdentifier::new(self.local_node_id, new_local_id).ok()?;
        let new_scoped_id = ScopedSessionId::new(new_server_id.to_owned(), new_id);

        let moved = {
            let mut register = self.register.write().await;
            let mut client_by_udp_address_guard = self.clients_by_udp_address.write();
            let mut client_by_host_guard = self.clients_by_host.write();

            let client = register.local_clients.remove(&old_scoped_id)?;
            register.channel_index_remove(&old_scoped_id);
            register.listener_index_remove_all(&old_scoped_id);

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
            client
        };

        self.release_local_session_id(old_server_id, old_id.local_session_id);

        if moved.is_published() {
            tracing::warn!(
                old_server_id,
                new_server_id,
                session = u32::from(old_id),
                "moved already-published local client across server scopes"
            );
        }

        Some(new_id)
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
    ) -> Arc<Box<Client>> {
        let server_id = server_id.into();
        let mut register = self.register.write().await;
        let mut client_by_udp_address_guard = self.clients_by_udp_address.write();
        let mut client_by_host_guard = self.clients_by_host.write();

        let id = self.allocate_local_session_id(&server_id);
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let scoped_id = ScopedSessionId::new(server_id.clone(), client_identifier);
        let client = Client::new_local_in_server(
            server_id,
            client_identifier,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection,
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

        client
    }

    pub async fn allocate_web_client(
        &self,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: tokio::sync::mpsc::Sender<crate::messages::Message>,
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
        outbound_tx: tokio::sync::mpsc::Sender<crate::messages::Message>,
    ) -> Arc<Box<Client>> {
        let server_id = server_id.into();
        let mut register = self.register.write().await;
        let mut client_by_host_guard = self.clients_by_host.write();

        let id = self.allocate_local_session_id(&server_id);
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let scoped_id = ScopedSessionId::new(server_id.clone(), client_identifier);
        let client = Client::new_web_gateway_in_server(
            server_id,
            client_identifier,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
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

        client
    }

    pub async fn allocate_moq_client_in_server(
        &self,
        server_id: impl Into<String>,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        local_address: SocketAddr,
        outbound_tx: tokio::sync::mpsc::Sender<crate::messages::Message>,
    ) -> Arc<Box<Client>> {
        let server_id = server_id.into();
        let mut register = self.register.write().await;
        let mut client_by_host_guard = self.clients_by_host.write();

        let id = self.allocate_local_session_id(&server_id);
        let client_identifier = ClientSessionIdentifier::new(self.local_node_id, id).unwrap();
        let scoped_id = ScopedSessionId::new(server_id.clone(), client_identifier);
        let client = Client::new_moq_gateway_in_server(
            server_id,
            client_identifier,
            real_ip_address,
            tcp_address,
            local_address,
            outbound_tx,
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

        client
    }

    /// Emit the `AddClient` log entry for a client that has completed
    /// authentication.  Sets the `published` flag so that future
    /// `remove_client` calls will emit a corresponding `RemoveClient`.
    pub async fn publish_client(&self, id: ClientSessionIdentifier) {
        self.publish_client_in_server(DEFAULT_SERVER_ID, id).await;
    }

    pub async fn publish_client_in_server(&self, server_id: &str, id: ClientSessionIdentifier) {
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        let client = match self
            .register
            .read()
            .await
            .local_clients
            .get(&scoped_id)
            .cloned()
        {
            Some(c) => c,
            None => return,
        };

        client.set_published(true);

        let initial_state = ClientGlobalStateDelta::from_global_state(&client.read_global_state());
        self.commit_operation(
            ClientStateOperation::AddClient {
                server_id: server_id.to_owned(),
                session_id: id,
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
        )
        .await;
    }

    pub async fn add_remote_client(&self, id: ClientSessionIdentifier, client: Arc<Box<Client>>) {
        let node_id = client.get_node_id();
        if node_id == self.local_node_id {
            panic!("Not supposed to add a remote client with the local node ID");
        }
        let server_id = client.server_id();
        let scoped_id = ScopedSessionId::new(server_id.clone(), id);

        // Snapshot fields before moving into the map
        let real_ip = client.get_real_ip_address();
        let tcp_addr = client.get_tcp_address();
        let udp_addr = client.get_udp_address();
        let cert_hash = client
            .get_certificate_hash()
            .map(bytes::Bytes::copy_from_slice);
        let login_time = client.get_login_time();
        let initial_state = ClientGlobalStateDelta::from_global_state(&client.read_global_state());

        {
            let mut register = self.register.write().await;
            register
                .remote_clients
                .entry(node_id)
                .or_default()
                .insert(scoped_id, client);
            // Ensure version/log entries exist for this node
            register.versions.entry(node_id).or_insert(0);
            register.remote_logs.entry(node_id).or_default();
            // NOTE: remote clients are intentionally NOT added to the channel
            // index — voice routing only targets local clients (remote
            // clients receive audio via S2S from their owning node).
        }

        // ── Log the operation ───────────────────────────────────────────
        self.commit_operation(
            ClientStateOperation::AddClient {
                server_id,
                session_id: id,
                real_ip,
                tcp_addr,
                udp_addr,
                local_addr: tcp_addr, // remote clients don't have a separate local addr
                cert_hash,
                login_time,
                initial_state,
            },
            None,
        )
        .await;
    }

    pub async fn remove_client(&self, id: ClientSessionIdentifier) -> Option<Arc<Box<Client>>> {
        self.remove_client_in_server(DEFAULT_SERVER_ID, id).await
    }

    pub async fn remove_client_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
    ) -> Option<Arc<Box<Client>>> {
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        let client = {
            let mut register = self.register.write().await;
            let mut client_by_udp_address_guard = self.clients_by_udp_address.write();
            let mut client_by_host_guard = self.clients_by_host.write();

            // Try local first, then remote
            let client = if let Some(c) = register.local_clients.remove(&scoped_id) {
                c
            } else if let Some(remote_map) = register.remote_clients.get_mut(&id.node_id) {
                match remote_map.remove(&scoped_id) {
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

            // The index only tracks local clients — these calls are no-ops
            // for remote clients but still safe to run unconditionally.
            register.channel_index_remove(&scoped_id);
            register.listener_index_remove_all(&scoped_id);

            if client.get_node_id() == self.local_node_id {
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

                self.release_local_session_id(scoped_id.server_id(), id.local_session_id);
            }
            client
        };

        if client.is_published() {
            self.commit_operation(
                ClientStateOperation::RemoveClient {
                    server_id: server_id.to_owned(),
                    session_id: id,
                },
                None,
            )
            .await;
        }

        Some(client)
    }

    pub async fn clear_clients_from_node(&self, node_id: u16) {
        if node_id == self.local_node_id {
            panic!("Not supposed to clear clients from the local node");
        }

        let (ids_to_remove, published): (Vec<ScopedSessionId>, Vec<bool>) = {
            let mut register = self.register.write().await;

            // Collect published status before removing from map
            let result = match register.remote_clients.get(&node_id) {
                Some(remote_map) => {
                    let ids: Vec<ScopedSessionId> = remote_map.keys().cloned().collect();
                    let pub_flags: Vec<bool> = ids
                        .iter()
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

            result
        };

        // ── Log each removal (only if client was published) ─────────────
        for (id, was_published) in ids_to_remove.iter().zip(published.iter()) {
            if *was_published {
                self.commit_operation(
                    ClientStateOperation::RemoveClient {
                        server_id: id.server_id().to_owned(),
                        session_id: id.session_id(),
                    },
                    None,
                )
                .await;
            }
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
        self.register
            .read()
            .await
            .get(&scoped_id, self.local_node_id)
            .cloned()
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
        self.register
            .read()
            .await
            .get(&id, self.local_node_id)
            .cloned()
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
            .filter_map(|id| register.get(id, self.local_node_id).cloned())
            .collect()
    }

    // ── Broadcast helpers ─────────────────────────────────────────────────

    /// Send `message` to every connected client.
    pub async fn broadcast_all(&self, message: &crate::messages::Message) {
        self.broadcast_all_in_server(DEFAULT_SERVER_ID, message)
            .await;
    }

    pub async fn broadcast_all_in_server(
        &self,
        server_id: &str,
        message: &crate::messages::Message,
    ) {
        let register = self.register.read().await;
        for client in register.local_clients() {
            if client.server_id() != server_id {
                continue;
            }
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
        self.broadcast_except_in_server(DEFAULT_SERVER_ID, exclude, message)
            .await;
    }

    pub async fn broadcast_except_in_server(
        &self,
        server_id: &str,
        exclude: ClientSessionIdentifier,
        message: &crate::messages::Message,
    ) {
        let register = self.register.read().await;
        let exclude_key = ScopedSessionId::new(server_id.to_owned(), exclude);
        for (id, client) in &register.local_clients {
            if *id == exclude_key || id.server_id() != server_id {
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
        self.broadcast_batch_except_in_server(DEFAULT_SERVER_ID, exclude, messages)
            .await;
    }

    pub async fn broadcast_batch_except_in_server(
        &self,
        server_id: &str,
        exclude: ClientSessionIdentifier,
        messages: &[crate::messages::Message],
    ) {
        let register = self.register.read().await;
        let exclude_key = ScopedSessionId::new(server_id.to_owned(), exclude);
        for (id, client) in &register.local_clients {
            if *id == exclude_key || id.server_id() != server_id {
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

    pub async fn get_all_clients_in_server(&self, server_id: &str) -> Vec<Arc<Box<Client>>> {
        self.register
            .read()
            .await
            .all_clients()
            .filter(|client| client.server_id() == server_id)
            .cloned()
            .collect()
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
            .filter_map(|id| register.get(id, self.local_node_id).cloned())
            .collect()
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
                    if let Some(c) = register.get(id, self.local_node_id) {
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
            .filter_map(|id| register.get(id, self.local_node_id).cloned())
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
                    if let Some(c) = register.get(id, self.local_node_id) {
                        result.push(c.clone());
                    }
                }
            }
        }
        result
    }

    /// Build a channel/listener interest snapshot for S2S voice node targeting.
    /// Local and replicated remote clients are included by their owning node id.
    pub async fn voice_recipient_index_snapshot(
        &self,
    ) -> std::collections::HashMap<u32, std::collections::BTreeSet<u16>> {
        let register = self.register.read().await;
        let mut snapshot: std::collections::HashMap<u32, std::collections::BTreeSet<u16>> =
            std::collections::HashMap::new();
        for (id, client) in register.all_entries() {
            if id.server_id() != DEFAULT_SERVER_ID {
                continue;
            }
            snapshot
                .entry(client.get_current_channel_id())
                .or_default()
                .insert(id.session_id().get_node_id());
            for listener_channel in client.get_listening_channel_ids() {
                snapshot
                    .entry(listener_channel)
                    .or_default()
                    .insert(id.session_id().get_node_id());
            }
        }
        snapshot
    }

    pub async fn len(&self) -> usize {
        let register = self.register.read().await;
        register.local_clients.len()
            + register
                .remote_clients
                .values()
                .map(|m| m.len())
                .sum::<usize>()
    }

    pub async fn len_in_server(&self, server_id: &str) -> usize {
        let register = self.register.read().await;
        register
            .all_clients()
            .filter(|client| client.server_id() == server_id)
            .count()
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
    /// Returns `(clients, versions)` where `versions` maps `node_id → version`.
    pub async fn snapshot_with_versions(&self) -> (Vec<Arc<Box<Client>>>, HashMap<u16, u64>) {
        let register = self.register.read().await;
        let clients: Vec<_> = register.all_clients().cloned().collect();
        (clients, register.versions.clone())
    }

    pub async fn snapshot_with_versions_in_server(
        &self,
        server_id: &str,
    ) -> (Vec<Arc<Box<Client>>>, HashMap<u16, u64>) {
        let register = self.register.read().await;
        let clients: Vec<_> = register
            .all_clients()
            .filter(|client| client.server_id() == server_id)
            .cloned()
            .collect();
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
        self.replay_since_in_server(DEFAULT_SERVER_ID, last_seen)
            .await
    }

    pub async fn replay_since_in_server(
        &self,
        server_id: &str,
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
                        oldest.version,
                        local_since,
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
            if entry.version > local_since && entry.op.server_id() == server_id {
                entries.push(entry);
            }
        }

        for (node_id, log) in &register.remote_logs {
            let since = last_seen.get(node_id).copied().unwrap_or(0);
            for entry in log {
                if entry.version > since && entry.op.server_id() == server_id {
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
        self.send_to_in_server(DEFAULT_SERVER_ID, id, message).await
    }

    pub async fn send_to_in_server(
        &self,
        server_id: &str,
        id: ClientSessionIdentifier,
        message: &crate::messages::Message,
    ) -> bool {
        let scoped_id = ScopedSessionId::new(server_id.to_owned(), id);
        let client = {
            let register = self.register.read().await;
            register.get(&scoped_id, self.local_node_id).cloned()
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
        self.register
            .try_read()
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
        let broadcast = {
            let mut register = self.register.write().await;
            let remote_node = op.node_id;
            let server_id = op.op.server_id().to_owned();

            // Check version against the remote node's tracked version and pending window.
            let current_ver = register.versions.get(&remote_node).copied().unwrap_or(0);
            let pending_max_ver = register
                .pending_remote_ops
                .iter()
                .filter(|(pending, _)| pending.node_id == remote_node)
                .map(|(pending, _)| pending.version)
                .max()
                .unwrap_or(current_ver);
            if op.version <= pending_max_ver {
                return Ok(());
            }
            let must_wait_for_pending = !register.pending_remote_ops.is_empty();

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

            if must_wait_for_pending || effective_dep > current_channel_version {
                tracing::debug!(
                    server_id = %server_id,
                    waiting_for_pending = must_wait_for_pending,
                    "Buffering remote client op v{} (node {}) — waiting for channel v{} (have v{})",
                    op.version,
                    remote_node,
                    effective_dep,
                    current_channel_version,
                );
                register
                    .last_pending_effective_dep_by_server
                    .insert(server_id, effective_dep);
                register.pending_remote_ops.push_back((op, effective_dep));
                return Ok(());
            }

            Self::apply_op_inner(&mut register, &op, remote_node);
            Some(Arc::new(ClientStateBroadcastPayload {
                entry: Arc::clone(&op),
                versions: register.versions.clone(),
            }))
        };

        if let Some(broadcast) = broadcast {
            let _ = self.tx.send(broadcast);
        }
        Ok(())
    }

    /// Drain pending remote ops for `server_id` whose effective dependency is <= `channel_version`.
    /// Called after channel state in that server scope is advanced.
    pub async fn drain_pending_ops(&self, server_id: &str, channel_version: u64) {
        let mut broadcasts = Vec::new();
        {
            let mut register = self.register.write().await;
            register
                .pending_channel_versions
                .entry(server_id.to_owned())
                .and_modify(|version| *version = (*version).max(channel_version))
                .or_insert(channel_version);

            loop {
                let Some((op, effective_dep)) = register.pending_remote_ops.front() else {
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

                let (op, _) = register.pending_remote_ops.pop_front().unwrap();
                let remote_node = op.node_id;
                tracing::debug!(
                    server_id = %op_server_id,
                    "Draining buffered remote client op v{} (node {}) at channel v{}",
                    op.version,
                    remote_node,
                    available_channel_version,
                );
                Self::apply_op_inner(&mut register, &op, remote_node);
                broadcasts.push(Arc::new(ClientStateBroadcastPayload {
                    entry: Arc::clone(&op),
                    versions: register.versions.clone(),
                }));
            }

            register.last_pending_effective_dep_by_server.clear();
            let pending: Vec<(String, u64)> = register
                .pending_remote_ops
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

        for broadcast in broadcasts {
            let _ = self.tx.send(broadcast);
        }
    }

    /// Apply a single remote op to the register (no version/buffer checks).
    fn apply_op_inner(register: &mut ClientRegister, op: &ClientStateLogEntry, remote_node: u16) {
        match &op.op {
            ClientStateOperation::AddClient {
                server_id,
                session_id,
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
                    ));
                    {
                        let mut gs = client.write_global_state_direct();
                        apply_delta_to_global_state(&mut gs, initial_state);
                    }
                    register
                        .remote_clients
                        .entry(remote_node)
                        .or_default()
                        .insert(scoped_id, client);
                }
            }
            ClientStateOperation::RemoveClient {
                server_id,
                session_id,
            } => {
                // Remote clients are not in the channel/listener index, so
                // no index cleanup is necessary here.
                let scoped_id = ScopedSessionId::new(server_id.clone(), *session_id);
                if let Some(remote_map) = register.remote_clients.get_mut(&remote_node) {
                    remote_map.remove(&scoped_id);
                    if remote_map.is_empty() {
                        register.remote_clients.remove(&remote_node);
                    }
                }
            }
            ClientStateOperation::UpdateGlobalState {
                server_id,
                session_id,
                sender_session_id: _,
                delta,
            } => {
                // Remote-only path: do NOT touch the local channel/listener
                // index — those exist solely for routing voice to local
                // recipients on this node.
                let scoped_id = ScopedSessionId::new(server_id.clone(), *session_id);
                let client = register.get(&scoped_id, remote_node).cloned();
                if let Some(client) = client {
                    let mut gs = client.write_global_state_direct();
                    apply_delta_to_global_state(&mut gs, delta);
                }
            }
        }

        let log = register.remote_logs.entry(remote_node).or_default();
        log.push_back(Arc::new(op.clone()));
        register.versions.insert(remote_node, op.version);
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
    ) {
        self.commit_operation_sync(op, channel_version_dep);
    }

    /// Synchronous version of `commit_operation`.  Safe to call from
    /// `Drop` impls (uses `try_write`).
    pub(crate) fn commit_operation_sync(
        &self,
        op: ClientStateOperation,
        channel_version_dep: Option<u64>,
    ) {
        let broadcast = {
            let mut register = match self.register.try_write() {
                Ok(r) => r,
                Err(_) => return, // deadlock avoidance in Drop contexts
            };

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
                    return;
                }
            }

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
                channel_version_dep,
                op,
            });

            register.local_log.push_back(Arc::clone(&entry));
            while register.local_log.len() > self.log_max_entries {
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::messages::{encoder::TextMessage, Message};
    use chrono::Utc;

    use super::*;

    #[tokio::test]
    async fn web_client_allocation_produces_local_writable_client() {
        let repo = ClientRepository::new(1, 128);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 34567);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);

        let client = repo.allocate_web_client(peer.ip(), peer, local, tx).await;
        assert_eq!(client.get_node_id(), 1);
        assert_eq!(repo.local_len().await, 1);

        let message = Message::TextMessage(
            TextMessage {
                actor: Some(12),
                session: Vec::new(),
                channel_id: Vec::new(),
                tree_id: Vec::new(),
                message: "hello".to_string(),
            }
            .into(),
        );
        client.write_proto_message(&message).await.unwrap();

        let queued = rx.recv().await.unwrap();
        match queued {
            Message::TextMessage(text) => assert_eq!(text.message, "hello"),
            other => panic!("expected TextMessage, got {other:?}"),
        }
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
        assert_eq!(alpha.server_id(), "alpha");
        assert_eq!(beta.server_id(), "beta");
        assert_eq!(repo_a.local_len_in_server("alpha").await, 1);
        assert_eq!(repo_a.local_len_in_server("beta").await, 0);
        assert!(repo_a
            .get_client_in_server("alpha", alpha.get_session_id())
            .await
            .is_some());
        assert!(repo_a
            .get_client_in_server("beta", alpha.get_session_id())
            .await
            .is_none());
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
                sender_session_id: None,
                delta: ClientGlobalStateDelta {
                    display_name: Some(Some("beta user".to_string())),
                    ..Default::default()
                },
            },
        });

        repo.apply_remote_operation(alpha_add, 4).await.unwrap();
        repo.apply_remote_operation(beta_update, 5).await.unwrap();

        assert!(repo
            .get_client_in_server("alpha", remote_session)
            .await
            .is_none());

        repo.drain_pending_ops("beta", 5).await;
        assert!(repo
            .get_client_in_server("alpha", remote_session)
            .await
            .is_none());

        repo.drain_pending_ops("alpha", 5).await;
        assert!(repo
            .get_client_in_server("alpha", remote_session)
            .await
            .is_some());
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
