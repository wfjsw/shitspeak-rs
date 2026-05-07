use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
};

use chrono::{DateTime, Utc};
use bytes::Bytes;
use parking_lot::{
    MappedMutexGuard as ParkingMappedMutexGuard,
    Mutex as ParkingMutex,
    MutexGuard as ParkingMutexGuard,
    RwLock as ParkingRwLock,
    RwLockReadGuard as ParkingRwLockReadGuard,
    RwLockWriteGuard as ParkingRwLockWriteGuard,
};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard, RwLock, RwLockWriteGuard, mpsc},
};
use tokio_rustls::server::TlsStream;

use crate::{
    client::{
        client_global_state::ClientGlobalState,
        client_local_state::ClientLocalState,
        client_session_identifier::ClientSessionIdentifier,
        client_stats::ClientStats,
        crypt::CryptState,
        global_state_guard::GlobalStateWriteGuard,
        options::ClientOptions,
        udp_state::UdpState,
        user_info::UserInfoExtended,
    },
    client_repository::ClientRepository,
    errors::{ReadProtoMessageError, WriteProtoMessageError},
    messages::{Message, ReadMessageExt, WriteMessageExt, encoder as msg_encoder},
    voice::VoiceRoutingPayload,
    protocol_version::ProtocolVersion,
};

const VOICE_ROUTING_QUEUE_CAPACITY: usize = 256;
const VOICE_TCP_QUEUE_CAPACITY: usize = 256;

pub struct Client {
    session_id: ClientSessionIdentifier,

    real_ip_address: IpAddr,
    tcp_address: SocketAddr,
    udp_address: Option<SocketAddr>,
    local_address: SocketAddr,

    connection_rx: AsyncMutex<ReadHalf<TlsStream<TcpStream>>>,
    connection_tx: AsyncMutex<WriteHalf<TlsStream<TcpStream>>>,
    is_verified: bool,

    // Statistics
    login_time: DateTime<Utc>,
    last_active: ParkingMutex<DateTime<Utc>>,
    last_ping: ParkingMutex<DateTime<Utc>>,
    udp_state: Option<AsyncMutex<UdpState>>,
    stats: RwLock<ClientStats>,

    certificate_hash: Option<Bytes>,
    user_info_extended: ParkingMutex<Option<UserInfoExtended>>,

    options: RwLock<ClientOptions>,

    local_state: ParkingRwLock<Option<ClientLocalState>>,
    global_state: ParkingRwLock<ClientGlobalState>,
    crypt_state: ParkingMutex<Option<CryptState>>,
    voice_routing_tx: mpsc::Sender<VoiceRoutingPayload>,
    voice_routing_rx: ParkingMutex<Option<mpsc::Receiver<VoiceRoutingPayload>>>,
    /// Per-user outgoing TCP voice tunnel queue.  The routing task pushes raw
    /// `UDPTunnel` payload bytes here without awaiting the TCP write; a
    /// dedicated per-user task drains the queue and writes them to the TLS
    /// stream serially.  This decouples the routing fan-out from per-recipient
    /// TCP backpressure.
    voice_tcp_tx: mpsc::Sender<Bytes>,
    voice_tcp_rx: ParkingMutex<Option<mpsc::Receiver<Bytes>>>,

    /// Whether this client has been published to the log (i.e. `AddClient`
    /// has been emitted).  Only published clients generate `RemoveClient`
    /// log entries on disconnect.
    published: AtomicBool,

    /// If true, send voice through TCP `UDPTunnel` instead of UDP.
    /// This is toggled when tunneled voice is received and reset once
    /// a valid UDP voice packet is seen again.
    prefer_tcp_tunnel: AtomicBool,

    /// The last client-state log version this connection has seen,
    /// indexed by node_id.  Used to detect gaps and replay missed entries.
    last_client_version: ParkingMutex<HashMap<u16, u64>>,
    /// The last channel-state log version this connection has seen.
    /// Channels are fully serialized across the cluster, so a single
    /// version counter suffices.
    last_channel_version: ParkingMutex<u64>,
}

impl Client {
    pub fn new_local(
        session_id: ClientSessionIdentifier,
        real_ip_address: IpAddr,
        tcp_address: SocketAddr,
        udp_address: Option<SocketAddr>,
        local_address: SocketAddr,
        connection: TlsStream<TcpStream>,
    ) -> Box<Self> {
        let (certificate_hash, is_verified) = {
            let (_, tls_connection) = connection.get_ref();
            let cert_hash = match tls_connection.peer_certificates() {
                Some([cert, ..]) => {
                    Some(Bytes::copy_from_slice(
                        aws_lc_rs::digest::digest(
                            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                            cert.as_ref(),
                        )
                        .as_ref(),
                    ))
                }
                _ => None,
            };
            let verified = tls_connection.peer_certificates().map_or(false, |c| !c.is_empty());
            (cert_hash, verified)
        };

        let now = Utc::now();

        let (voice_routing_tx, voice_routing_rx) =
            mpsc::channel::<VoiceRoutingPayload>(VOICE_ROUTING_QUEUE_CAPACITY);
        let (voice_tcp_tx, voice_tcp_rx) =
            mpsc::channel::<Bytes>(VOICE_TCP_QUEUE_CAPACITY);

        let (connection_rx, connection_tx) = tokio::io::split(connection);

        Box::new(Client {
            session_id,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection_rx: AsyncMutex::new(connection_rx),
            connection_tx: AsyncMutex::new(connection_tx),
            is_verified,
            login_time: now,
            last_active: ParkingMutex::new(now),
            last_ping: ParkingMutex::new(now),
            udp_state: None,
            stats: RwLock::new(ClientStats::default()),
            certificate_hash,
            user_info_extended: ParkingMutex::new(Some(UserInfoExtended::default())),
            options: RwLock::new(ClientOptions::default()),
            local_state: ParkingRwLock::new(Some(ClientLocalState::new())),
            global_state: ParkingRwLock::new(ClientGlobalState::new()),
            crypt_state: ParkingMutex::new(None),
            voice_routing_tx,
            voice_routing_rx: ParkingMutex::new(Some(voice_routing_rx)),
            voice_tcp_tx,
            voice_tcp_rx: ParkingMutex::new(Some(voice_tcp_rx)),
            published: AtomicBool::new(false),
            prefer_tcp_tunnel: AtomicBool::new(false),
            last_client_version: ParkingMutex::new(HashMap::new()),
            last_channel_version: ParkingMutex::new(0),
        })
    }

    pub fn is_registered(&self) -> bool {
        self.global_state.read().is_registered()
    }

    pub fn has_certificate(&self) -> bool {
        self.certificate_hash.is_some()
    }

    pub fn is_published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }

    pub fn set_published(&self, value: bool) {
        self.published.store(value, Ordering::Release);
    }

    pub fn set_prefer_tcp_tunnel(&self, value: bool) {
        self.prefer_tcp_tunnel.store(value, Ordering::Release);
    }

    pub fn prefers_tcp_tunnel(&self) -> bool {
        self.prefer_tcp_tunnel.load(Ordering::Acquire)
    }

    /// Get a clone of the full per-node last-seen version map.
    pub async fn get_last_client_versions(&self) -> HashMap<u16, u64> {
        self.last_client_version.lock().clone()
    }

    /// Merge the given per-node version map into the client's last-seen
    /// trackers.  Each entry is updated to `max(existing, new)`.
    pub async fn update_last_client_versions(&self, versions: &HashMap<u16, u64>) {
        let mut map = self.last_client_version.lock();
        for (&node_id, &version) in versions {
            let entry = map.entry(node_id).or_insert(0);
            *entry = (*entry).max(version);
        }
    }

    /// Get the last channel-state version seen.
    pub async fn get_last_channel_version(&self) -> u64 {
        *self.last_channel_version.lock()
    }

    /// Record a channel-state version seen.
    pub async fn set_last_channel_version(&self, version: u64) {
        *self.last_channel_version.lock() = version;
    }

    pub fn get_groups_clone(&self) -> HashSet<String> {
        self.global_state.read().get_groups().clone()
    }

    pub fn has_group(&self, group: &str) -> bool {
        self.global_state.read().has_group(group)
    }

    pub fn get_certificate_hash(&self) -> Option<&[u8]> {
        self.certificate_hash.as_deref()
    }

    pub fn get_session_id(&self) -> ClientSessionIdentifier {
        self.session_id
    }

    pub fn get_node_id(&self) -> u16 {
        self.session_id.get_node_id()
    }

    pub fn get_local_session_id(&self) -> u32 {
        self.session_id.get_local_session_id()
    }

    pub fn get_tokens_clone(&self) -> HashSet<String> {
        self.global_state.read().get_tokens().clone()
    }

    pub fn has_token(&self, token: &str) -> bool {
        self.global_state.read().has_token(token)
    }

    pub fn get_current_channel_id(&self) -> u32 {
        self.global_state.read().get_current_channel_id()
    }

    pub fn set_current_channel_id(&self, channel_id: u32, repo: &ClientRepository, channel_version: u64) {
        let mut gs = self.write_global_state_as(repo, Some(self.session_id), Some(channel_version));
        gs.set_current_channel_id(channel_id);
    }

    pub fn get_user_id(&self) -> Option<u32> {
        self.global_state.read().get_user_id()
    }

    // pub fn get_display_name(&self) -> Option<String> {
    //     match &*self.user_info.lock() {
    //         Some(info) => Some(info.get_display_name().clone()),
    //         None => match &self.user_info_extended {
    //             Some(ext) => Some(ext.lock().username.clone()),
    //             None => None,
    //         },
    //     }
    // }

    pub fn get_tcp_address(&self) -> SocketAddr {
        self.tcp_address
    }

    pub fn get_udp_address(&self) -> Option<SocketAddr> {
        self.udp_address
    }

    pub fn get_real_ip_address(&self) -> IpAddr {
        self.real_ip_address
    }

    pub fn get_login_time(&self) -> DateTime<Utc> {
        self.login_time
    }
    // FIXME: not sure if it is verified or just exists
    pub async fn is_verified(&self) -> bool {
        self.is_verified
    }

    pub fn disconnect(&self) {
        todo!();
    }

    pub async fn read_proto_message(&self) -> Result<Message, ReadProtoMessageError> {
        let mut guard = self.connection_rx.lock().await;
        guard.read_proto_message().await
    }

    // TODO: instead of a straight write, this should be actually queued and batched so to reduce
    // the number of syscalls and TLS record overhead, when there is a burst of messages to send. 
    // When doing it, we should also ensure that messages are not delayed too much. 
    // That may requires some careful engineering.
    pub async fn write_proto_message(
        &self,
        message: &Message,
    ) -> Result<(), WriteProtoMessageError> {
        let mut guard = self.connection_tx.lock().await;
        guard.write_proto_message(message).await
    }

    /// Send multiple messages in a single syscall burst.
    ///
    /// Serialises all messages into one contiguous buffer and issues a single
    /// `write_all`, avoiding the per-message syscall overhead that would
    /// accumulate when sending channel trees or user-state bursts.
    pub async fn write_proto_message_batch(
        &self,
        messages: &[Message],
    ) -> Result<(), WriteProtoMessageError> {
        let mut guard = self.connection_tx.lock().await;
        guard.write_proto_message_batch(messages).await
    }

    pub fn set_tokens(&self, tokens: HashSet<String>, repo: &ClientRepository) {
        let mut gs = self.write_global_state(repo);
        gs.set_tokens(tokens);
    }

    pub async fn get_last_ping(&self) -> DateTime<Utc> {
        let last_ping = self.last_ping.lock();
        *last_ping
    }

    pub async fn reset_last_ping(&self) {
        let mut last_ping = self.last_ping.lock();
        *last_ping = Utc::now();
    }

    // pub async fn update_from_ping_message(&self, ping_message: &Ping) {
    //     {
    //         let mut crypt_state = self.crypt_state.lock().await;
    //         if let Some(state) = crypt_state.as_mut() {
    //             state.update_from_ping_message(ping_message);
    //         }
    //     }

    //     {
    //         let mut stats = self.stats.write().await;
    //         stats.update_from_ping_message(ping_message);
    //     }
    // }

    pub fn crypt_state(&self) -> ParkingMutexGuard<'_, Option<CryptState>> {
        self.crypt_state.lock()
    }

    pub async fn udp_state(&self) -> AsyncMutexGuard<'_, UdpState> {
        match &self.udp_state {
            Some(m) => m.lock().await,
            None => panic!("UDP state not initialized"),
        }
    }

    pub fn create_crypt_state(
        &self,
        mode: &str,
    ) -> Result<(), crate::client::crypt::CryptError> {
        let mut state = self.crypt_state.lock();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        *state = Some(CryptState::generate(mode, &rng)?);
        Ok(())
    }

    pub fn push_voice_routing(&self, decoded_audio: crate::voice::codec::DecodedAudio, is_udp: bool) {
        let payload = VoiceRoutingPayload { decoded_audio, is_udp };
        if self.voice_routing_tx.try_send(payload).is_err() {
            tracing::trace!(session = u32::from(self.session_id), "voice routing queue full or closed, dropping packet");
        }
    }

    /// Take the receiver half of the voice routing queue.  Called once by
    /// `spawn_voice_routing_task`; returns `None` on any subsequent call.
    pub fn take_voice_routing_rx(&self) -> Option<mpsc::Receiver<VoiceRoutingPayload>> {
        self.voice_routing_rx.lock().take()
    }

    /// Enqueue an already-encoded `UDPTunnel` payload for transmission to
    /// this client over its TCP voice tunnel.  Non-blocking: returns
    /// immediately, dropping the packet if the queue is full or closed.
    ///
    /// In debug builds a full queue triggers a `debug_assert!` panic since it
    /// indicates the per-user TCP send task is not keeping up; in release
    /// builds the packet is silently dropped (voice is realtime, backlog is
    /// worse than loss).
    pub fn try_enqueue_voice_tcp(&self, raw: Bytes) {
        match self.voice_tcp_tx.try_send(raw) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug_assert!(
                    false,
                    "voice TCP queue full for session {}",
                    u32::from(self.session_id)
                );
                tracing::trace!(
                    session = u32::from(self.session_id),
                    "voice TCP queue full, dropping packet"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::trace!(
                    session = u32::from(self.session_id),
                    "voice TCP queue closed, dropping packet"
                );
            }
        }
    }

    /// Take the receiver half of the voice TCP send queue.  Called once by
    /// `spawn_voice_tcp_task`; returns `None` on any subsequent call.
    pub fn take_voice_tcp_rx(&self) -> Option<mpsc::Receiver<Bytes>> {
        self.voice_tcp_rx.lock().take()
    }

    pub async fn write_stats(&self) -> RwLockWriteGuard<'_, ClientStats> {
        self.stats.write().await
    }

    // pub async fn create_ping_response(&self, ping_message: &Ping) -> Ping {
    //     let crypt_state = self.crypt_state.lock().await;
    //     if let Some(state) = crypt_state.as_ref() {
    //         state.create_ping_response(ping_message)
    //     } else {
    //         ping_message.default_from_self()
    //     }
    // }

    pub fn is_authenticated(&self) -> bool {
        let local_state_guard = self.local_state.read();
        match &*local_state_guard {
            Some(state) => state.is_authenticated(),
            None => panic!("Accessing local state on remote user"),
        }
    }

    /// Returns `true` if this client has superuser privileges.
    ///
    /// A client is a superuser if they are authenticated and belong to the
    /// `admin` group.
    pub fn is_superuser(&self) -> bool {
        self.has_group("admin")
    }

    pub fn set_authenticated(&self, value: bool) {
        let mut local_state_guard = self.local_state.write();
        match &mut *local_state_guard {
            Some(state) => state.set_authenticated(value),
            None => panic!("Accessing local state on remote user"),
        }
    }

    pub fn set_protocol_version(&self, version: Option<ProtocolVersion>, repo: &ClientRepository) {
        let mut gs = self.write_global_state(repo);
        gs.set_protocol_version(version);
    }

    pub fn set_release(&self, release: Option<String>) {
        let mut local_state_guard = self.local_state.write();
        if let Some(ref mut state) = *local_state_guard {
            state.set_release(release);
        }
    }

    pub fn set_os(&self, os: Option<String>) {
        let mut local_state_guard = self.local_state.write();
        if let Some(ref mut state) = *local_state_guard {
            state.set_os(os);
        }
    }

    pub fn set_os_version(&self, os_version: Option<String>) {
        let mut local_state_guard = self.local_state.write();
        if let Some(ref mut state) = *local_state_guard {
            state.set_os_version(os_version);
        }
    }

    pub fn read_global_state(&self) -> ParkingRwLockReadGuard<'_, ClientGlobalState> {
        self.global_state.read()
    }

    pub fn read_local_state(&self) -> ParkingRwLockReadGuard<'_, Option<ClientLocalState>> {
        self.local_state.read()
    }

    pub fn write_local_state(&self) -> ParkingRwLockWriteGuard<'_, Option<ClientLocalState>> {
        self.local_state.write()
    }

    /// Acquire a transactional write guard for `ClientGlobalState`.
    ///
    /// Mutations made through the guard are batched: when the guard is dropped
    /// (or `commit()` is called explicitly), a `ClientGlobalStateDelta` is
    /// computed, a `ClientStateLogEntry` is created, and the global version
    /// is bumped by exactly 1.
    pub fn write_global_state<'a>(
        &'a self,
        repo: &'a ClientRepository,
    ) -> GlobalStateWriteGuard<'a> {
        self.write_global_state_as(repo, Some(self.session_id), None)
    }

    /// Acquire a transactional write guard for `ClientGlobalState` while
    /// explicitly recording who initiated the mutation and the channel
    /// version dependency.
    ///
    /// `channel_version_dep`: `Some(v)` means this mutation depends on
    /// channel state at version `v` or later. `None` means no dependency.
    pub fn write_global_state_as<'a>(
        &'a self,
        repo: &'a ClientRepository,
        sender_session_id: Option<ClientSessionIdentifier>,
        channel_version_dep: Option<u64>,
    ) -> GlobalStateWriteGuard<'a> {
        let inner = self.global_state.write();
        GlobalStateWriteGuard::new(inner, repo, self.session_id, sender_session_id, channel_version_dep)
    }

    /// Direct (non-transactional) write access to `ClientGlobalState`.
    /// Only for internal use (e.g. `apply_remote_operation`).
    /// Callers should prefer `write_global_state(repo)` for normal mutations.
    pub fn write_global_state_direct(&self) -> ParkingRwLockWriteGuard<'_, ClientGlobalState> {
        self.global_state.write()
    }

    /// Build a `UserState` snapshot of this client suitable for broadcasting
    /// to other clients (i.e. everything a peer needs to know about this user).
    /// Not suitable for continuous update of clients state.
    pub fn build_user_state_for_broadcast(&self) -> msg_encoder::UserState {
        let gs = self.global_state.read();

        let comment_hash_bytes = gs
            .get_comment_hash()
            .and_then(|h| hex::decode(h).ok().map(Bytes::from));
        let texture_hash_bytes = gs
            .get_texture_hash()
            .and_then(|h| hex::decode(h).ok().map(Bytes::from));

        msg_encoder::UserState {
            session: Some(self.session_id),
            actor: None,
            name: gs.get_display_name_opt().map(|s| s.to_owned()),
            user_id: gs.get_user_id(),
            channel_id: Some(gs.get_current_channel_id()),
            mute: if gs.is_muted() { Some(true) } else { None },
            deaf: if gs.is_deafened() { Some(true) } else { None },
            suppress: if gs.is_suppressed() { Some(true) } else { None },
            self_mute: if gs.is_self_muted() { Some(true) } else { None },
            self_deaf: if gs.is_self_deafened() { Some(true) } else { None },
            texture: None,
            plugin_context: if gs.get_plugin_context().is_empty() { None } else { Some(Bytes::copy_from_slice(gs.get_plugin_context())) },
            plugin_identity: if gs.get_plugin_identity().is_empty() { None } else { Some(gs.get_plugin_identity().to_owned()) },
            comment: None,
            hash: self.certificate_hash.as_ref().map(|h| hex::encode(h)),
            comment_hash: comment_hash_bytes,
            texture_hash: texture_hash_bytes,
            priority_speaker: if gs.is_priority_speaker() { Some(true) } else { None },
            recording: if gs.is_recording() { Some(true) } else { None },
            temporary_access_tokens: Vec::new(),
            listening_channel_add: gs.get_listening_channel_id().iter().copied().collect(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        }
    }

    pub async fn user_info_extended(&self) -> ParkingMappedMutexGuard<'_, UserInfoExtended> {
        let user_info_extended = self.user_info_extended.lock();
        if user_info_extended.is_none() {
            panic!("Accessing user_info_extended of non-local user");
        }
        ParkingMutexGuard::map(user_info_extended, |opt| opt.as_mut().unwrap())
    }
}
