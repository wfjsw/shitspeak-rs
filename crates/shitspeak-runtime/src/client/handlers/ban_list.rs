use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use shitspeak_state::{BanEntry, BanOp};

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, encoder::BanList},
    server::Server,
};

const BANNED_ADDRESS_LENGTH: usize = 16;

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
                mask: if b.ban_ip { b.mask as u32 } else { 0 },
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
            let max_mask: u32 = if address.is_ipv4() { 32 } else { 128 };
            if ban_ip && b.mask > max_mask {
                return Err(MessageHandlerError::protocol_violation(
                    "ban list contains an invalid mask for its address family",
                ));
            }
            entries.push(BanEntry {
                address,
                mask: b.mask as u8,
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
        if !server.s2s_manager().propose_ban_op(op).await {
            if let Err(e) = server.get_bans().set_bans(entries).await {
                tracing::warn!("Failed to persist ban list: {e}");
            }
        }
        tracing::info!(
            "Ban list update from session {:?} with {} entries",
            sender.get_session_id(),
            msg.bans.len()
        );
    }

    Ok(())
}
