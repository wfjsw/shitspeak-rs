use std::{net::{IpAddr, SocketAddr}, sync::atomic::AtomicBool};

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use tokio::net::TcpStream;

use crate::client::{client_stats::ClientStats, options::ClientOptions, states::UserState, udp_state::UdpState, user_info::UserInfo, user_version::UserVersion};

pub struct Client {
    session_id: u32,

    real_ip_address: IpAddr,
    tcp_address: SocketAddr,
    udp_address: SocketAddr,
    local_address: SocketAddr,

    connection: TcpStream,
    connection_state: Mutex<UserState>,
    
    // This is only concerned if the client is a local client
    has_userlist: Option<AtomicBool>,
    
    // Statistics
    login_time: DateTime<Utc>,
    last_active: Option<Mutex<DateTime<Utc>>>,
    last_ping: Option<Mutex<DateTime<Utc>>>,
    udp_state: Option<Mutex<UdpState>>,
    stats: Option<RwLock<ClientStats>>,

    // Might be a registered user, might not
    // Basic user info are synchronized.
    user_id: u32,
    certificate_hash: String,
    user_info: Mutex<Option<UserInfo>>,
    user_info_extended: Option<Mutex<UserInfo>>,

    user_version: UserVersion, // rather constant
    
    options: RwLock<ClientOptions>
}
