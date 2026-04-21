use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt},
    mumble_proto::UserStats,
    server::Server,
};

pub async fn handle_user_stats(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserStats,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

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

    let now = chrono::Utc::now();
    let login_time = target.get_login_time();
    let onlinesecs = (now - login_time).num_seconds() as u32;

    let version = gs.get_protocol_version().map(|v| {
        let v_u64: u64 = v.into();
        crate::mumble_proto::Version {
            version_v1: Some(v_u64 as u32),
            version_v2: Some(v_u64),
            release: gs.get_release().map(|s| s.to_owned()),
            os: gs.get_os_name().map(|s| s.to_owned()),
            os_version: gs.get_os_version().map(|s| s.to_owned()),
        }
    });

    let reply = Message::UserStats(UserStats {
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
        address: Some(sender.get_real_ip_address().to_string().into_bytes()),
        bandwidth: Some(0), // TODO: bandwidth tracking
        onlinesecs: Some(onlinesecs),
        idlesecs: Some(0), // TODO: idle tracking
        strong_certificate: Some(sender.has_certificate()),
        opus: Some(true),
        rolling_stats: None,
    });

    sender.write_proto_message(&reply).await?;
    Ok(())
}
