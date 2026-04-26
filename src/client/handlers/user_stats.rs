use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{encoder::UserStats, Message, WriteMessageExt},
    server::Server,
};

pub async fn handle_user_stats(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserStats,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Err(MessageHandlerError::protocol_violation(
            "UserStats message received before authentication",
        ));
    }

    tracing::debug!(session = u32::from(sender.get_session_id()), target = msg.session, stats_only = msg.stats_only, "UserStats handler");

    // If the client is requesting stats for a specific session, look it up.
    // Otherwise, return stats for the sender.
    let target = match msg.session {
        Some(session_id) if session_id != u32::from(sender.get_session_id()) => {
            let target_id =
                crate::client::client_session_identifier::ClientSessionIdentifier::from(session_id);
            match server.get_clients().get_client(target_id).await {
                Some(c) => c,
                None => return Ok(()),
            }
        }
        _ => sender.clone(),
    };

    let stats = target.write_stats().await;
    let gs = target.read_global_state().await;
    let local_state = target.read_local_state().await;
    let local = local_state.as_ref();

    let now = chrono::Utc::now();
    let login_time = target.get_login_time();
    let onlinesecs = (now - login_time).num_seconds() as u32;

    let version = gs.get_protocol_version().map(|v| {
        let v_u64: u64 = v.into();
        crate::messages::encoder::Version {
            version: Some(crate::protocol_version::ProtocolVersion::from(v_u64)),
            release: local.and_then(|l| l.get_release().map(|s| s.to_owned())),
            os: local.and_then(|l| l.get_os_name().map(|s| s.to_owned())),
            os_version: local.and_then(|l| l.get_os_version().map(|s| s.to_owned())),
        }.into()
    });

    let reply: Message = UserStats {
        session: Some(u32::from(target.get_session_id())),
        stats_only: msg.stats_only,
        certificates: Vec::new(), // TODO: TLS cert chain
        from_client: None,
        from_server: None,
        udp_packets: Some(stats.udp_packets()),
        tcp_packets: Some(stats.tcp_packets()),
        udp_ping_avg: Some(stats.udp_ping_avg()),
        udp_ping_var: Some(stats.udp_ping_var()),
        tcp_ping_avg: Some(stats.tcp_ping_avg()),
        tcp_ping_var: Some(stats.tcp_ping_var()),
        version,
        celt_versions: Vec::new(),
        address: Some(sender.get_real_ip_address()),
        bandwidth: Some(0), // TODO: bandwidth tracking
        onlinesecs: Some(onlinesecs),
        idlesecs: Some(0), // TODO: idle tracking
        strong_certificate: Some(sender.has_certificate()),
        opus: Some(true),
    }.into();

    sender.write_proto_message(&reply).await?;
    Ok(())
}
