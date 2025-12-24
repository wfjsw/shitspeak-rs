use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::atomic::AtomicBool,
};

use chrono::{DateTime, Utc};
use parking_lot::{lock_api::MappedMutexGuard, Mutex, MutexGuard, RwLock};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tokio_rustls::server::TlsStream;

use crate::{client::{
    client_session_identifier::ClientSessionIdentifier,
    client_session_state::ClientSessionState,
    client_stats::ClientStats,
    options::ClientOptions,
    states::ConnectionState,
    udp_state::UdpState,
    user_info::{UserInfo, UserInfoExtended},
    user_version::UserVersion,
}, messages::{Message}};

pub struct Client {
    session_id: ClientSessionIdentifier,

    real_ip_address: IpAddr,
    tcp_address: SocketAddr,
    udp_address: Option<SocketAddr>,
    local_address: SocketAddr,

    connection: TlsStream<TcpStream>,
    connection_state: Mutex<ConnectionState>,

    // This is only concerned if the client is a local client
    has_userlist: Option<AtomicBool>,

    // Statistics
    login_time: DateTime<Utc>,
    last_active: Mutex<DateTime<Utc>>,
    last_ping: Mutex<DateTime<Utc>>,
    udp_state: Option<Mutex<UdpState>>,
    stats: RwLock<ClientStats>,

    // Might be a registered user, might not
    // Basic user info are synchronized.
    user_id: Option<u32>,
    certificate_hash: Option<Vec<u8>>,
    user_info: Mutex<Option<UserInfo>>,
    user_info_extended: Option<Mutex<UserInfoExtended>>,

    user_version: Option<UserVersion>, // rather constant

    options: RwLock<ClientOptions>,

    session_state: Option<RwLock<ClientSessionState>>,
}

impl Client {
    pub fn new(
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
            connection,
            user_version: None,
            has_userlist: None,
            login_time: now,
            last_active: Mutex::new(now),
            last_ping: Mutex::new(now),
            udp_state: None,
            stats: RwLock::new(ClientStats::default()),
            user_id: None,
            certificate_hash,
            user_info: Mutex::new(None),
            user_info_extended: None,
            options: RwLock::new(ClientOptions::default()),
            session_state: None,
            connection_state: Mutex::new(ConnectionState::Connected),
        })
    }

    pub fn is_registered(&self) -> bool {
        self.user_id.is_some()
    }

    pub fn has_certificate(&self) -> bool {
        self.certificate_hash.is_some()
    }

    pub fn get_groups(
        &self,
    ) -> Option<MappedMutexGuard<'_, parking_lot::RawMutex, HashSet<String>>> {
        MutexGuard::try_map(self.user_info.lock(), |maybe_info| {
            maybe_info.as_mut().map(|info| info.get_groups_mut())
        })
        .ok()
    }

    pub fn get_groups_clone(&self) -> Option<HashSet<String>> {
        match &*self.user_info.lock() {
            Some(info) => Some(info.get_groups().clone()),
            None => None,
        }
    }

    pub fn has_group(&self, group: &str) -> bool {
        match &*self.user_info.lock() {
            Some(info) => info.has_group(group),
            None => false,
        }
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

    pub fn get_tokens(&self) -> Option<HashSet<String>> {
        match &*self.user_info.lock() {
            Some(info) => Some(info.get_tokens().clone()),
            None => None,
        }
    }

    pub fn has_token(&self, token: &str) -> bool {
        match &*self.user_info.lock() {
            Some(info) => info.has_token(token),
            None => false,
        }
    }

    pub fn get_current_channel_id(&self) -> u32 {
        self.session_state
            .as_ref()
            .map_or(0, |state| state.read().get_current_channel_id())
    }

    pub fn set_current_channel_id(&self, channel_id: u32) {
        if let Some(state) = &self.session_state {
            state.write().set_current_channel_id(channel_id);
        }
    }

    pub fn get_user_id(&self) -> Option<u32> {
        self.user_id
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
    pub fn is_verified(&self) -> bool {
        let (_, conn) = self.connection.get_ref();
        conn.peer_certificates()
            .map_or(false, |certs| !certs.is_empty())
    }

    pub fn disconnect(&self) {

    }

}
