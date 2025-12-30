use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

use chrono::{DateTime, Utc};
use tokio::{
    net::TcpStream,
    sync::{MappedMutexGuard, Mutex, MutexGuard, RwLock},
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
    messages::{Message, ReadMessageExt, WriteMessageExt},
    mumble_proto::Ping,
};

pub struct Client {
    pub(crate) session_id: ClientSessionIdentifier,

    pub(crate) real_ip_address: IpAddr,
    pub(crate) tcp_address: SocketAddr,
    pub(crate) udp_address: Option<SocketAddr>,
    pub(crate) local_address: SocketAddr,

    pub(crate) connection: Mutex<TlsStream<TcpStream>>,

    // Statistics
    pub(crate) login_time: DateTime<Utc>,
    pub(crate) last_active: Mutex<DateTime<Utc>>,
    pub(crate) last_ping: Mutex<DateTime<Utc>>,
    pub(crate) udp_state: Option<Mutex<UdpState>>,
    pub(crate) stats: RwLock<ClientStats>,

    // Might be a registered user, might not
    // Basic user info are synchronized.
    pub(crate) certificate_hash: Option<Vec<u8>>,
    pub(crate) user_info: RwLock<UserInfo>,
    pub(crate) user_info_extended: Mutex<Option<UserInfoExtended>>,

    pub(crate) options: RwLock<ClientOptions>,

    pub(crate) local_state: RwLock<Option<ClientLocalState>>,
    pub(crate) global_state: RwLock<ClientGlobalState>,
    pub(crate) crypt_state: Mutex<Option<CryptState>>,
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

    pub async fn update_from_ping_message(&self, ping_message: &Ping) {
        {
            let mut crypt_state = self.crypt_state.lock().await;
            if let Some(state) = crypt_state.as_mut() {
                state.update_from_ping_message(ping_message);
            }
        }

        {
            let mut stats = self.stats.write().await;
            stats.update_from_ping_message(ping_message);
        }
    }

    pub async fn create_ping_response(&self, ping_message: &Ping) -> Ping {
        let crypt_state = self.crypt_state.lock().await;
        if let Some(state) = crypt_state.as_ref() {
            state.create_ping_response(ping_message)
        } else {
            Ping {
                good: Some(0),
                late: Some(0),
                lost: Some(0),
                resync: Some(0),
                timestamp: ping_message.timestamp,
                udp_packets: None,
                tcp_packets: None,
                udp_ping_avg: None,
                udp_ping_var: None,
                tcp_ping_avg: None,
                tcp_ping_var: None,
            }
        }
    }

    pub async fn is_authenticated(&self) -> bool {
        let local_state_guard = self.local_state.read().await;
        match &*local_state_guard {
            Some(state) => state.is_authenticated(),
            None => panic!("Accessing local state on remote user"),
        }
    }
}
