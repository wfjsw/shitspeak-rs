use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
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
        crypt::{CryptState, CryptoMode},
        options::ClientOptions,
        states::ConnectionState,
        udp_state::UdpState,
        user_info::{UserInfo, UserInfoExtended},
    },
    errors::{ReadProtoMessageError, WriteProtoMessageError},
    messages::{encoder::Ping, Message, ReadMessageExt, WriteMessageExt},
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

    // Might be a registered user, might not
    // Basic user info are synchronized.
    certificate_hash: Option<Vec<u8>>,
    user_info: RwLock<UserInfo>,
    user_info_extended: Mutex<Option<UserInfoExtended>>,

    options: RwLock<ClientOptions>,

    local_state: RwLock<Option<ClientLocalState>>,
    global_state: RwLock<ClientGlobalState>,
    crypt_state: Mutex<Option<CryptState>>,
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
            user_info: RwLock::new(UserInfo::default()),
            user_info_extended: Mutex::new(None),
            options: RwLock::new(ClientOptions::default()),
            local_state: RwLock::new(Some(ClientLocalState::new())),
            global_state: RwLock::new(ClientGlobalState::new()),
            crypt_state: Mutex::new(None),
        })
    }

    pub async fn is_registered(&self) -> bool {
        let state = self.global_state.read().await;
        state.get_user_id().is_some()
    }

    pub fn has_certificate(&self) -> bool {
        self.certificate_hash.is_some()
    }

    pub async fn get_groups_clone(&self) -> HashSet<String> {
        let user_info = self.user_info.read().await;
        user_info.get_groups().clone()
    }

    pub async fn has_group(&self, group: &str) -> bool {
        let user_info = self.user_info.read().await;
        user_info.has_group(group)
    }

    pub fn get_certificate_hash(&self) -> Option<&[u8]> {
        self.certificate_hash.as_deref()
    }

    pub fn get_session_id(&self) -> u32 {
        self.session_id.into()
    }

    pub fn get_node_id(&self) -> u16 {
        self.session_id.get_node_id()
    }

    pub fn get_local_session_id(&self) -> u32 {
        self.session_id.get_local_session_id()
    }

    pub async fn get_tokens_clone(&self) -> HashSet<String> {
        let user_info = self.user_info.read().await;
        user_info.get_tokens().clone()
    }

    pub async fn has_token(&self, token: &str) -> bool {
        let user_info = self.user_info.read().await;
        user_info.has_token(token)
    }

    pub async fn get_current_channel_id(&self) -> u32 {
        self.global_state.read().await.get_current_channel_id()
    }

    pub async fn set_current_channel_id(&self, channel_id: u32) {
        self.global_state
            .write()
            .await
            .set_current_channel_id(channel_id);
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
    // FIXME: not sure if it is verified or just exists
    pub async fn is_verified(&self) -> bool {
        let guard = self.connection.lock().await;
        let (_, conn) = guard.get_ref();
        conn.peer_certificates()
            .map_or(false, |certs| !certs.is_empty())
    }

    pub fn disconnect(&self) {}

    pub async fn read_proto_message(&self) -> Result<Message, ReadProtoMessageError> {
        let mut guard = self.connection.lock().await;
        guard.read_proto_message().await
    }

    pub async fn write_proto_message(
        &self,
        message: &Message,
    ) -> Result<(), WriteProtoMessageError> {
        let mut guard = self.connection.lock().await;
        guard.write_proto_message(message).await
    }

    pub async fn set_tokens(&self, tokens: HashSet<String>) {
        let mut user_info = self.user_info.write().await;
        user_info.set_tokens(tokens);
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

    pub async fn crypt_state(
        &self,
    ) -> MutexGuard<'_, Option<CryptState>> {
        self.crypt_state.lock().await
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

    pub async fn set_protocol_version(&self, version: Option<ProtocolVersion>) {
        let mut global_state_guard = self.global_state.write().await;
        global_state_guard.set_protocol_version(version);
    }

    pub async fn set_release(&self, release: Option<String>) {
        let mut global_state_guard = self.global_state.write().await;
        global_state_guard.set_release(release);
    }

    pub async fn set_os(&self, os: Option<String>) {
        let mut global_state_guard = self.global_state.write().await;
        global_state_guard.set_os(os);
    }

    pub async fn set_os_version(&self, os_version: Option<String>) {
        let mut global_state_guard = self.global_state.write().await;
        global_state_guard.set_os_version(os_version);
    }

    pub async fn read_global_state(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, ClientGlobalState> {
        self.global_state.read().await
    }

    pub async fn write_global_state(
        &self,
    ) -> RwLockWriteGuard<'_, ClientGlobalState> {
        self.global_state.write().await
    }

    pub async fn user_info_extended(
        &self,
    ) -> MutexGuard<'_, Option<UserInfoExtended>> {
        self.user_info_extended.lock().await
    }

}
