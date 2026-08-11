use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use shitspeak_state::{BanEntry, BanOp};

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, encoder::BanList},
    s2s::BanProposalOutcome,
    server::Server,
};

use super::{
    BAN_REPOSITORY_REQUEST_ADMITTED, BAN_REPOSITORY_REQUEST_REJECTED,
    BAN_REPOSITORY_REQUEST_SUBMITTED, send_ban_repository_notice,
};

const BANNED_ADDRESS_LENGTH: usize = 16;
const IPV4_MAPPED_MASK_OFFSET: u32 = 96;

fn decode_ban_address(address: &[u8]) -> Result<IpAddr, MessageHandlerError> {
    let address: [u8; BANNED_ADDRESS_LENGTH] = address.try_into().map_err(|_| {
        MessageHandlerError::protocol_violation(
            "ban list address must contain a 16-byte Mumble HostAddress",
        )
    })?;
    let address = Ipv6Addr::from(address);

    Ok(address
        .to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(address)))
}

fn encode_ban_address(address: IpAddr, ban_ip: bool) -> Vec<u8> {
    if !ban_ip {
        return vec![0; BANNED_ADDRESS_LENGTH];
    }

    match address {
        IpAddr::V4(address) => {
            let mut encoded = [0; BANNED_ADDRESS_LENGTH];
            encoded[10] = 0xff;
            encoded[11] = 0xff;
            encoded[12..].copy_from_slice(&address.octets());
            encoded.to_vec()
        }
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn decode_ban_mask(address: IpAddr, ban_ip: bool, mask: u32) -> Result<u8, MessageHandlerError> {
    if !ban_ip {
        return Ok(0);
    }

    match address {
        IpAddr::V4(_) => {
            if !(IPV4_MAPPED_MASK_OFFSET..=IPV4_MAPPED_MASK_OFFSET + 32).contains(&mask) {
                return Err(MessageHandlerError::protocol_violation(
                    "ban list contains an invalid mask for its address family",
                ));
            }
            Ok((mask - IPV4_MAPPED_MASK_OFFSET) as u8)
        }
        IpAddr::V6(_) if mask <= 128 => Ok(mask as u8),
        IpAddr::V6(_) => Err(MessageHandlerError::protocol_violation(
            "ban list contains an invalid mask for its address family",
        )),
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

pub async fn handle_ban_list(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: BanList,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "BanList message received before authentication",
        ));
    }

    tracing::debug!(
        session = u32::from(sender.get_session_id()),
        query = msg.query,
        num_bans = msg.bans.len(),
        "BanList handler"
    );

    let root_perms = crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
    if !root_perms.contains(shitspeak_state::ACLPermissions::Ban) {
        return Err(MessageHandlerError::PermissionDenied(
            shitspeak_messages::messages::encoder::PermissionDenied::for_permission(
                u32::from(sender.get_session_id()),
                Some(0),
                shitspeak_state::ACLPermissions::Ban,
            ),
        ));
    }

    if msg.query.unwrap_or(false) {
        // Query mode: return current ban list
        let active = server.get_bans().get_active_bans().await;
        let bans: Vec<shitspeak_proto::mumble_proto::ban_list::BanEntry> = active
            .into_iter()
            .map(|b| shitspeak_proto::mumble_proto::ban_list::BanEntry {
                address: encode_ban_address(b.address, b.ban_ip),
                mask: encode_ban_mask(b.address, b.ban_ip, b.mask),
                name: b.name.clone(),
                hash: b.hash.clone(),
                reason: b.reason.clone(),
                start: Some(b.start.to_string()),
                duration: Some(b.duration as u32),
            })
            .collect();
        let reply: Message = BanList {
            bans,
            query: Some(false),
        }
        .into();
        sender.write_proto_message(&reply).await?;
    } else {
        // Update mode: replace ban list with provided entries
        let mut entries: Vec<BanEntry> = Vec::with_capacity(msg.bans.len());
        for b in &msg.bans {
            // Mumble represents every BanEntry address as a 16-byte HostAddress.
            // IPv4 entries are IPv4-mapped IPv6 addresses, not UTF-8 text.
            let address = decode_ban_address(&b.address)?;
            let ban_ip = !address.is_unspecified();
            let mask = decode_ban_mask(address, ban_ip, b.mask)?;
            entries.push(BanEntry {
                address,
                mask,
                name: b.name.clone(),
                hash: b.hash.clone(),
                ban_certificate: b.hash.is_some(),
                ban_ip,
                reason: b.reason.clone(),
                start: b
                    .start
                    .as_ref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(chrono::Utc::now().timestamp()),
                duration: b.duration.unwrap_or(0) as u64,
            });
        }

        let op = BanOp::SetBans {
            entries: entries.clone(),
        };
        send_ban_repository_notice(sender, BAN_REPOSITORY_REQUEST_SUBMITTED).await?;
        let proposal_outcome = server.s2s_manager().propose_ban_op(op).await;
        let admitted = if proposal_outcome.permits_direct_repository_fallback() {
            match server.get_bans().set_bans(entries).await {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!("Failed to persist ban list: {error}");
                    false
                }
            }
        } else {
            proposal_outcome == BanProposalOutcome::Admitted
        };
        if admitted {
            send_ban_repository_notice(sender, BAN_REPOSITORY_REQUEST_ADMITTED).await?;
        } else {
            send_ban_repository_notice(sender, BAN_REPOSITORY_REQUEST_REJECTED).await?;
        }
        tracing::info!(
            "Ban list update from session {:?} with {} entries",
            sender.get_session_id(),
            msg.bans.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{decode_ban_address, decode_ban_mask, encode_ban_mask};

    #[test]
    fn ipv4_mapped_ban_masks_round_trip_at_the_mumble_protocol_boundary() {
        let address =
            decode_ban_address(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]).unwrap();

        assert_eq!(address, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(decode_ban_mask(address, true, 128).unwrap(), 32);
        assert_eq!(encode_ban_mask(address, true, 32), 128);
        assert!(decode_ban_mask(address, true, 32).is_err());
    }

    #[test]
    fn ipv6_ban_masks_are_not_translated() {
        let address = IpAddr::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(decode_ban_mask(address, true, 128).unwrap(), 128);
        assert_eq!(encode_ban_mask(address, true, 128), 128);
        assert!(decode_ban_mask(address, true, 129).is_err());
    }
}
