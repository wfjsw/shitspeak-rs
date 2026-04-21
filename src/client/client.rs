use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
};

use chrono::{DateTime, Utc};
use tokio::{
    net::TcpStream,
    sync::{MappedMutexGuard, Mutex, MutexGuard, RwLock, RwLockWriteGuard},
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
    protocol_version::ProtocolVersion,
};

pub struct Client {
    session_id: ClientSessionIdentifier,

    real_ip_address: IpAddr,
    tcp_address: SocketAddr,
    udp_address: Option<SocketAddr>,
    local_address: SocketAddr,

    connection: Mutex<TlsStream<TcpStream>>,

    // Statistics
    login_time: DateTime<Utc>,
    last_active: Mutex<DateTime<Utc>>,
    last_ping: Mutex<DateTime<Utc>>,
    udp_state: Option<Mutex<UdpState>>,
    stats: RwLock<ClientStats>,

    certificate_hash: Option<Vec<u8>>,
    user_info_extended: Mutex<Option<UserInfoExtended>>,

    options: RwLock<ClientOptions>,

    local_state: RwLock<Option<ClientLocalState>>,
    global_state: RwLock<ClientGlobalState>,
    crypt_state: Mutex<Option<CryptState>>,

    /// Whether this client has been published to the log (i.e. `AddClient`
    /// has been emitted).  Only published clients generate `RemoveClient`
    /// log entries on disconnect.
    published: AtomicBool,
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
        let certificate_hash = {
            let (_, tls_connection) = connection.get_ref();
            match tls_connection.peer_certificates() {
                Some([cert, ..]) => {
                    // Compute the hash of the peer certificate
                    Some(
                        aws_lc_rs::digest::digest(
                            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
                            cert.as_ref(),
                        )
                        .as_ref()
                        .to_vec(),
                    )
                }
                _ => None,
            }
        };

        let now = Utc::now();

        Box::new(Client {
            session_id,
            real_ip_address,
            tcp_address,
            udp_address,
            local_address,
            connection: Mutex::new(connection),
            login_time: now,
            last_active: Mutex::new(now),
            last_ping: Mutex::new(now),
            udp_state: None,
            stats: RwLock::new(ClientStats::default()),
            certificate_hash,
            user_info_extended: Mutex::new(Some(UserInfoExtended::default())),
            options: RwLock::new(ClientOptions::default()),
            local_state: RwLock::new(Some(ClientLocalState::new())),
            global_state: RwLock::new(ClientGlobalState::new()),
            crypt_state: Mutex::new(None),
            published: AtomicBool::new(false),
        })
    }

    pub async fn is_registered(&self) -> bool {
        self.global_state.read().await.is_registered()
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

    pub async fn get_groups_clone(&self) -> HashSet<String> {
        self.global_state.read().await.get_groups().clone()
    }

    pub async fn has_group(&self, group: &str) -> bool {
        let gs = self.global_state.read().await;
        gs.has_group(group)
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

    pub async fn get_tokens_clone(&self) -> HashSet<String> {
        let gs = self.global_state.read().await;
        gs.get_tokens().clone()
    }

    pub async fn has_token(&self, token: &str) -> bool {
        let gs = self.global_state.read().await;
        gs.has_token(token)
    }

    pub async fn get_current_channel_id(&self) -> u32 {
        self.global_state.read().await.get_current_channel_id()
    }

    pub async fn set_current_channel_id(&self, channel_id: u32, repo: &ClientRepository) {
        let mut gs = self.write_global_state(repo).await;
        gs.set_current_channel_id(channel_id);
    }

    pub async fn get_user_id(&self) -> Option<u32> {
        self.global_state.read().await.get_user_id()
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
        let guard = self.connection.lock().await;
        let (_, conn) = guard.get_ref();
        conn.peer_certificates()
            .map_or(false, |certs| !certs.is_empty())
    }

    pub fn disconnect(&self) {
        todo!();
    }

    pub async fn read_proto_message(&self) -> Result<Message, ReadProtoMessageError> {
        let mut guard = self.connection.lock().await;
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
        let mut guard = self.connection.lock().await;
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
        let mut guard = self.connection.lock().await;
        guard.write_proto_message_batch(messages).await
    }

    pub async fn set_tokens(&self, tokens: HashSet<String>, repo: &ClientRepository) {
        let mut gs = self.write_global_state(repo).await;
        gs.set_tokens(tokens);
    }

    pub async fn get_last_ping(&self) -> DateTime<Utc> {
        let last_ping = self.last_ping.lock().await;
        *last_ping
    }

    pub async fn reset_last_ping(&self) {
        let mut last_ping = self.last_ping.lock().await;
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

    pub async fn crypt_state(&self) -> MutexGuard<'_, Option<CryptState>> {
        self.crypt_state.lock().await
    }

    pub async fn udp_state(&self) -> MutexGuard<'_, UdpState> {
        match &self.udp_state {
            Some(m) => m.lock().await,
            None => panic!("UDP state not initialized"),
        }
    }

    pub async fn create_crypt_state(
        &self,
        mode: &str,
    ) -> Result<(), crate::client::crypt::CryptError> {
        let mut state = self.crypt_state.lock().await;
        // FIXME: store RNG elsewhere
        // This RNG should be global to the entire program, preferably.
        let rng = aws_lc_rs::rand::SystemRandom::new();
        *state = Some(CryptState::generate(mode, &rng)?);
        Ok(())
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

    pub async fn is_authenticated(&self) -> bool {
        let local_state_guard = self.local_state.read().await;
        match &*local_state_guard {
            Some(state) => state.is_authenticated(),
            None => panic!("Accessing local state on remote user"),
        }
    }

    pub async fn set_authenticated(&self, value: bool) {
        let mut local_state_guard = self.local_state.write().await;
        match &mut *local_state_guard {
            Some(state) => state.set_authenticated(value),
            None => panic!("Accessing local state on remote user"),
        }
    }

    pub async fn set_protocol_version(&self, version: Option<ProtocolVersion>, repo: &ClientRepository) {
        let mut gs = self.write_global_state(repo).await;
        gs.set_protocol_version(version);
    }

    pub async fn set_release(&self, release: Option<String>) {
        let mut local_state_guard = self.local_state.write().await;
        if let Some(ref mut state) = *local_state_guard {
            state.set_release(release);
        }
    }

    pub async fn set_os(&self, os: Option<String>) {
        let mut local_state_guard = self.local_state.write().await;
        if let Some(ref mut state) = *local_state_guard {
            state.set_os(os);
        }
    }

    pub async fn set_os_version(&self, os_version: Option<String>) {
        let mut local_state_guard = self.local_state.write().await;
        if let Some(ref mut state) = *local_state_guard {
            state.set_os_version(os_version);
        }
    }

    pub async fn read_global_state(&self) -> tokio::sync::RwLockReadGuard<'_, ClientGlobalState> {
        self.global_state.read().await
    }

    pub async fn read_local_state(&self) -> tokio::sync::RwLockReadGuard<'_, Option<ClientLocalState>> {
        self.local_state.read().await
    }

    pub async fn write_local_state(&self) -> RwLockWriteGuard<'_, Option<ClientLocalState>> {
        self.local_state.write().await
    }

    /// Acquire a transactional write guard for `ClientGlobalState`.
    ///
    /// Mutations made through the guard are batched: when the guard is dropped
    /// (or `commit()` is called explicitly), a `ClientGlobalStateDelta` is
    /// computed, a `ClientStateLogEntry` is created, and the global version
    /// is bumped by exactly 1.
    pub async fn write_global_state<'a>(
        &'a self,
        repo: &'a ClientRepository,
    ) -> GlobalStateWriteGuard<'a> {
        let inner = self.global_state.write().await;
        GlobalStateWriteGuard::new(inner, repo, self.session_id)
    }

    /// Direct (non-transactional) write access to `ClientGlobalState`.
    /// Only for internal use (e.g. `apply_remote_operation`).
    /// Callers should prefer `write_global_state(repo)` for normal mutations.
    pub async fn write_global_state_direct(&self) -> RwLockWriteGuard<'_, ClientGlobalState> {
        self.global_state.write().await
    }

    /// Build a `UserState` snapshot of this client suitable for broadcasting
    /// to other clients (i.e. everything a peer needs to know about this user).
    pub async fn build_user_state_for_broadcast(&self) -> msg_encoder::UserState {
        let gs = self.global_state.read().await;

        let comment_hash_bytes = gs.get_comment_hash().and_then(|h| hex::decode(h).ok());
        let texture_hash_bytes = gs.get_texture_hash().and_then(|h| hex::decode(h).ok());

        msg_encoder::UserState {
            session: Some(self.session_id),
            actor: None,
            name: gs.get_display_name_opt().map(|s| s.to_owned()),
            user_id: gs.get_user_id(),
            channel_id: Some(gs.get_current_channel_id()),
            mute: Some(gs.is_muted()),
            deaf: Some(gs.is_deafened()),
            suppress: Some(gs.is_suppressed()),
            self_mute: Some(gs.is_self_muted()),
            self_deaf: Some(gs.is_self_deafened()),
            texture: None,
            plugin_context: if gs.get_plugin_context().is_empty() { None } else { Some(gs.get_plugin_context().to_vec()) },
            plugin_identity: if gs.get_plugin_identity().is_empty() { None } else { Some(gs.get_plugin_identity().to_owned()) },
            comment: None,
            hash: self.certificate_hash.as_ref().map(|h| hex::encode(h)),
            comment_hash: comment_hash_bytes,
            texture_hash: texture_hash_bytes,
            priority_speaker: Some(gs.is_priority_speaker()),
            recording: Some(gs.is_recording()),
            temporary_access_tokens: Vec::new(),
            listening_channel_add: gs.get_listening_channel_id().iter().copied().collect(),
            listening_channel_remove: Vec::new(),
            listening_volume_adjustment: Vec::new(),
        }
    }

    pub async fn user_info_extended(&self) -> MappedMutexGuard<'_, UserInfoExtended> {
        let user_info_extended = self.user_info_extended.lock().await;
        if user_info_extended.is_none() {
            panic!("Accessing user_info_extended of non-local user");
        }
        MutexGuard::map(user_info_extended, |opt| opt.as_mut().unwrap())
    }
}
