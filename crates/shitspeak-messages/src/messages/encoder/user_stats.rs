use crate::messages::Message;
use bytes::Bytes;
use rustls::pki_types::CertificateDer;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Default)]
pub struct UserStats {
    pub session: Option<u32>,
    pub stats_only: Option<bool>,
    pub certificates: Vec<CertificateDer<'static>>,
    pub from_client: Option<shitspeak_proto::mumble_proto::user_stats::Stats>,
    pub from_server: Option<shitspeak_proto::mumble_proto::user_stats::Stats>,
    pub udp_packets: Option<u32>,
    pub tcp_packets: Option<u32>,
    pub udp_ping_avg: Option<f32>,
    pub udp_ping_var: Option<f32>,
    pub tcp_ping_avg: Option<f32>,
    pub tcp_ping_var: Option<f32>,
    pub version: Option<shitspeak_proto::mumble_proto::Version>,
    pub celt_versions: Vec<i32>,
    pub address: Option<IpAddr>,
    pub bandwidth: Option<u32>,
    pub onlinesecs: Option<u32>,
    pub idlesecs: Option<u32>,
    pub strong_certificate: Option<bool>,
    pub opus: Option<bool>,
}

impl From<shitspeak_proto::mumble_proto::UserStats> for UserStats {
    fn from(proto: shitspeak_proto::mumble_proto::UserStats) -> Self {
        Self {
            session: proto.session,
            stats_only: proto.stats_only,
            certificates: proto
                .certificates
                .into_iter()
                .map(|cert| CertificateDer::from(cert.to_vec()))
                .collect(),
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
            address: proto
                .address
                .and_then(|raw| decode_ip_bytes(raw.as_slice())),
            bandwidth: proto.bandwidth,
            onlinesecs: proto.onlinesecs,
            idlesecs: proto.idlesecs,
            strong_certificate: proto.strong_certificate,
            opus: proto.opus,
        }
    }
}

impl From<UserStats> for shitspeak_proto::mumble_proto::UserStats {
    fn from(user_stats: UserStats) -> Self {
        shitspeak_proto::mumble_proto::UserStats {
            session: user_stats.session,
            stats_only: user_stats.stats_only,
            certificates: user_stats
                .certificates
                .into_iter()
                .map(|cert| Bytes::copy_from_slice(cert.as_ref()))
                .collect(),
            from_client: user_stats.from_client,
            from_server: user_stats.from_server,
            udp_packets: user_stats.udp_packets,
            tcp_packets: user_stats.tcp_packets,
            udp_ping_avg: user_stats.udp_ping_avg,
            udp_ping_var: user_stats.udp_ping_var,
            tcp_ping_avg: user_stats.tcp_ping_avg,
            tcp_ping_var: user_stats.tcp_ping_var,
            version: user_stats.version,
            celt_versions: user_stats.celt_versions,
            address: user_stats.address.map(encode_ip_bytes),
            bandwidth: user_stats.bandwidth,
            onlinesecs: user_stats.onlinesecs,
            idlesecs: user_stats.idlesecs,
            strong_certificate: user_stats.strong_certificate,
            opus: user_stats.opus,
            rolling_stats: None,
        }
    }
}

fn decode_ip_bytes(raw: &[u8]) -> Option<IpAddr> {
    match raw.len() {
        4 => {
            let addr: [u8; 4] = raw.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(addr)))
        }
        16 => {
            let addr: [u8; 16] = raw.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

fn encode_ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        // Mumble's HostAddress field always uses the 16-byte IPv6 wire format.
        // Encode IPv4 addresses as IPv4-mapped IPv6 addresses so clients display
        // the original IPv4 address rather than the unspecified IPv6 address.
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

impl From<UserStats> for Message {
    fn from(user_stats: UserStats) -> Self {
        Message::UserStats(user_stats.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ipv4_as_ipv4_mapped_ipv6() {
        let encoded = encode_ip_bytes(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));

        assert_eq!(
            encoded,
            Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped().octets()
        );
    }

    #[test]
    fn encodes_ipv6_as_native_ipv6() {
        let address: Ipv6Addr = "2001:db8::1".parse().unwrap();

        assert_eq!(encode_ip_bytes(IpAddr::V6(address)), address.octets());
    }
}
