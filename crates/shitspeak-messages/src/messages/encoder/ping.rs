use crate::messages::{Message, errors::PingProtocolError};

#[derive(Debug, Clone, Default)]
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

impl From<Ping> for crate::mumble_proto::Ping {
    fn from(value: Ping) -> Self {
        crate::mumble_proto::Ping {
            timestamp: Some(value.timestamp),
            good: Some(value.good),
            late: Some(value.late),
            lost: Some(value.lost),
            resync: Some(value.resync),
            udp_packets: value.udp_packets,
            tcp_packets: value.tcp_packets,
            udp_ping_avg: value.udp_ping_avg,
            udp_ping_var: value.udp_ping_var,
            tcp_ping_avg: value.tcp_ping_avg,
            tcp_ping_var: value.tcp_ping_var,
        }
    }
}

impl From<Ping> for Message {
    fn from(value: Ping) -> Self {
        Message::Ping(value.into())
    }
}
