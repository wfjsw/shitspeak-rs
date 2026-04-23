use crate::messages::Message;

#[derive(Debug, Clone)]
pub struct UserStats {
    pub session: Option<u32>,
    pub stats_only: Option<bool>,
    pub certificates: Vec<Vec<u8>>,
    pub from_client: Option<crate::mumble_proto::user_stats::Stats>,
    pub from_server: Option<crate::mumble_proto::user_stats::Stats>,
    pub udp_packets: Option<u32>,
    pub tcp_packets: Option<u32>,
    pub udp_ping_avg: Option<f32>,
    pub udp_ping_var: Option<f32>,
    pub tcp_ping_avg: Option<f32>,
    pub tcp_ping_var: Option<f32>,
    pub version: Option<crate::mumble_proto::Version>,
    pub celt_versions: Vec<i32>,
    pub address: Option<Vec<u8>>,
    pub bandwidth: Option<u32>,
    pub onlinesecs: Option<u32>,
    pub idlesecs: Option<u32>,
    pub strong_certificate: Option<bool>,
    pub opus: Option<bool>,
}

impl From<crate::mumble_proto::UserStats> for UserStats {
    fn from(proto: crate::mumble_proto::UserStats) -> Self {
        Self {
            session: proto.session,
            stats_only: proto.stats_only,
            certificates: proto.certificates,
            from_client: proto.from_client,
            from_server: proto.from_server,
            udp_packets: proto.udp_packets,
            tcp_packets: proto.tcp_packets,
            udp_ping_avg: proto.udp_ping_avg,
            udp_ping_var: proto.udp_ping_var,
            tcp_ping_avg: proto.tcp_ping_avg,
            tcp_ping_var: proto.tcp_ping_var,
            version: proto.version,
            celt_versions: proto.celt_versions,
            address: proto.address,
            bandwidth: proto.bandwidth,
            onlinesecs: proto.onlinesecs,
            idlesecs: proto.idlesecs,
            strong_certificate: proto.strong_certificate,
            opus: proto.opus,
        }
    }
}

impl Default for UserStats {
    fn default() -> Self {
        Self {
            session: None,
            stats_only: None,
            certificates: Vec::new(),
            from_client: None,
            from_server: None,
            udp_packets: None,
            tcp_packets: None,
            udp_ping_avg: None,
            udp_ping_var: None,
            tcp_ping_avg: None,
            tcp_ping_var: None,
            version: None,
            celt_versions: Vec::new(),
            address: None,
            bandwidth: None,
            onlinesecs: None,
            idlesecs: None,
            strong_certificate: None,
            opus: None,
        }
    }
}

impl Into<crate::mumble_proto::UserStats> for UserStats {
    fn into(self) -> crate::mumble_proto::UserStats {
        crate::mumble_proto::UserStats {
            session: self.session,
            stats_only: self.stats_only,
            certificates: self.certificates,
            from_client: self.from_client,
            from_server: self.from_server,
            udp_packets: self.udp_packets,
            tcp_packets: self.tcp_packets,
            udp_ping_avg: self.udp_ping_avg,
            udp_ping_var: self.udp_ping_var,
            tcp_ping_avg: self.tcp_ping_avg,
            tcp_ping_var: self.tcp_ping_var,
            version: self.version,
            celt_versions: self.celt_versions,
            address: self.address,
            bandwidth: self.bandwidth,
            onlinesecs: self.onlinesecs,
            idlesecs: self.idlesecs,
            strong_certificate: self.strong_certificate,
            opus: self.opus,
            rolling_stats: None,
        }
    }
}

impl Into<Message> for UserStats {
    fn into(self) -> Message {
        Message::UserStats(self.into())
    }
}
