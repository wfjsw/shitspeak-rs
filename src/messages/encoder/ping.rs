use crate::messages::{Message, errors::PingProtocolError};

#[derive(Debug, Clone)]
pub struct Ping {
    pub timestamp: u64,
    pub good: u32,
    pub late: u32,
    pub lost: u32,
    pub resync: u32,

    pub udp_packets: Option<u32>,
    pub tcp_packets: Option<u32>,
    pub udp_ping_avg: Option<f32>,
    pub udp_ping_var: Option<f32>,
    pub tcp_ping_avg: Option<f32>,
    pub tcp_ping_var: Option<f32>,
}


impl TryFrom<crate::mumble_proto::Ping> for Ping {
    fn try_from(proto: crate::mumble_proto::Ping) -> Result<Self, PingProtocolError> {
        Ok(Self {
            timestamp: proto.timestamp.ok_or(PingProtocolError::MissingTimestamp)?,
            good: proto.good.unwrap_or(0),
            late: proto.late.unwrap_or(0),
            lost: proto.lost.unwrap_or(0),
            resync: proto.resync.unwrap_or(0),
            udp_packets: proto.udp_packets,
            tcp_packets: proto.tcp_packets,
            udp_ping_avg: proto.udp_ping_avg,
            udp_ping_var: proto.udp_ping_var,
            tcp_ping_avg: proto.tcp_ping_avg,
            tcp_ping_var: proto.tcp_ping_var,
        })
    }
    type Error = PingProtocolError;
}

impl Ping {
    pub fn default_from_timestamp(timestamp: u64) -> Self {
        Self {
            timestamp,
            ..Self::default()
        }
    }

    pub fn default_from_self(&self) -> Self {
        Self {
            timestamp: self.timestamp,
            ..Self::default()
        }
    }

    pub fn default_from_message(message: &crate::mumble_proto::Ping) -> Self {
        Self {
            timestamp: message.timestamp.unwrap_or(0),
            ..Self::default()
        }
    }
}

impl Default for Ping {
    fn default() -> Self {
        Self {
            timestamp: 0,
            good: 0,
            late: 0,
            lost: 0,
            resync: 0,
            udp_packets: None,
            tcp_packets: None,
            udp_ping_avg: None,
            udp_ping_var: None,
            tcp_ping_avg: None,
            tcp_ping_var: None,
        }
    }
}

impl Into<crate::mumble_proto::Ping> for Ping {
    fn into(self) -> crate::mumble_proto::Ping {
        crate::mumble_proto::Ping {
            timestamp: Some(self.timestamp),
            good: Some(self.good),
            late: Some(self.late),
            lost: Some(self.lost),
            resync: Some(self.resync),
            udp_packets: self.udp_packets,
            tcp_packets: self.tcp_packets,
            udp_ping_avg: self.udp_ping_avg,
            udp_ping_var: self.udp_ping_var,
            tcp_ping_avg: self.tcp_ping_avg,
            tcp_ping_var: self.tcp_ping_var,
        }
    }
}

impl Into<Message> for Ping {
    fn into(self) -> Message {
        Message::Ping(self.into())
    }
}
