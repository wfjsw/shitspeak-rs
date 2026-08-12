use crate::messages::Message;
use std::net::IpAddr;

const BANNED_ADDRESS_LENGTH: usize = 16;
const IPV4_MAPPED_MASK_OFFSET: u32 = 96;

/// A ban entry expressed with a native IP address rather than Mumble's
/// 16-byte `HostAddress` wire representation.
///
/// These fields are public because callers in other crates construct outbound
/// BanList replies from their ban repositories.
#[derive(Debug, Clone)]
pub struct BanEntry {
    pub address: IpAddr,
    pub mask: u8,
    pub ban_ip: bool,
    pub name: Option<String>,
    pub hash: Option<String>,
    pub reason: Option<String>,
    pub start: Option<String>,
    pub duration: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct BanList {
    pub bans: Vec<BanEntry>,
    pub query: Option<bool>,
}

impl From<BanList> for shitspeak_proto::mumble_proto::BanList {
    fn from(value: BanList) -> Self {
        shitspeak_proto::mumble_proto::BanList {
            bans: value
                .bans
                .into_iter()
                .map(|ban| shitspeak_proto::mumble_proto::ban_list::BanEntry {
                    address: encode_ban_address(ban.address, ban.ban_ip),
                    mask: encode_ban_mask(ban.address, ban.ban_ip, ban.mask),
                    name: ban.name,
                    hash: ban.hash,
                    reason: ban.reason,
                    start: ban.start,
                    duration: ban.duration,
                })
                .collect(),
            query: value.query,
        }
    }
}

impl From<BanList> for Message {
    fn from(value: BanList) -> Self {
        Self::BanList(value.into())
    }
}

fn encode_ban_address(address: IpAddr, ban_ip: bool) -> Vec<u8> {
    if !ban_ip {
        return vec![0; BANNED_ADDRESS_LENGTH];
    }

    match address {
        IpAddr::V4(address) => address.to_ipv6_mapped().octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn encode_ban_mask(address: IpAddr, ban_ip: bool, mask: u8) -> u32 {
    if !ban_ip {
        return 0;
    }

    match address {
        // Mumble's IPv4 entries use an IPv4-mapped 16-byte HostAddress, so
        // their wire masks include the 96-bit mapping prefix.
        IpAddr::V4(_) => u32::from(mask) + IPV4_MAPPED_MASK_OFFSET,
        IpAddr::V6(_) => u32::from(mask),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{BanEntry, BanList};

    #[test]
    fn encodes_ipv4_bans_as_ipv4_mapped_host_addresses() {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let list: shitspeak_proto::mumble_proto::BanList = BanList {
            bans: vec![BanEntry {
                address: IpAddr::V4(address),
                mask: 24,
                ban_ip: true,
                name: None,
                hash: None,
                reason: None,
                start: None,
                duration: None,
            }],
            query: Some(false),
        }
        .into();

        assert_eq!(list.bans[0].address, address.to_ipv6_mapped().octets());
        assert_eq!(list.bans[0].mask, 120);
    }

    #[test]
    fn encodes_ipv6_bans_without_address_or_mask_translation() {
        let address: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let list: shitspeak_proto::mumble_proto::BanList = BanList {
            bans: vec![BanEntry {
                address: IpAddr::V6(address),
                mask: 64,
                ban_ip: true,
                name: None,
                hash: None,
                reason: None,
                start: None,
                duration: None,
            }],
            query: Some(false),
        }
        .into();

        assert_eq!(list.bans[0].address, address.octets());
        assert_eq!(list.bans[0].mask, 64);
    }

    #[test]
    fn encodes_certificate_only_bans_with_an_unspecified_address() {
        let list: shitspeak_proto::mumble_proto::BanList = BanList {
            bans: vec![BanEntry {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                mask: 24,
                ban_ip: false,
                name: None,
                hash: Some("certificate-hash".to_string()),
                reason: None,
                start: None,
                duration: None,
            }],
            query: Some(false),
        }
        .into();

        assert_eq!(list.bans[0].address, [0; 16]);
        assert_eq!(list.bans[0].mask, 0);
    }
}
