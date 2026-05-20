use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use prost::Message as _;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{encoder::UserStats, Message, WriteMessageExt},
    s2s::application::proto::UserStatsRequest,
    s2s::application::user_stats::{UserStatsApplyOutcome, UserStatsResponder},
    server::Server,
    types::NodeIdentifier,
};

pub async fn handle_user_stats(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserStats,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "UserStats message received before authentication",
        ));
    }

    tracing::debug!(
        session = u32::from(sender.get_session_id()),
        target = msg.session,
        stats_only = msg.stats_only,
        "UserStats handler"
    );

    let sender_id = sender.get_session_id();
    let server_id = sender.server_id();
    let local_node_id = server.get_clients().local_node_id();
    let stats_only = msg.stats_only.unwrap_or(false);
    let sender_raw = u32::from(sender_id);

    let target_session_raw = msg.session.unwrap_or(sender_raw);
    let target_session =
        crate::client::client_session_identifier::ClientSessionIdentifier::from(target_session_raw);

    let mut effective_stats_only = stats_only;
    if target_session != sender_id {
        if let Some(target_state) = server
            .get_clients()
            .get_client_in_server(&server_id, target_session)
            .await
        {
            let target_channel = target_state.get_current_channel_id();
            let root_perms =
                crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
            if !root_perms.contains(crate::acl::ACLPermissions::Ban) {
                let target_channel_perms = crate::client::acl::compute_permissions_for_client(
                    server,
                    sender,
                    target_channel,
                )
                .await;
                if !target_channel_perms.contains(crate::acl::ACLPermissions::Enter) {
                    return Err(MessageHandlerError::PermissionDenied(
                        crate::messages::encoder::PermissionDenied::for_permission(
                            sender_raw,
                            Some(target_channel),
                            crate::acl::ACLPermissions::Enter,
                        ),
                    ));
                }
                effective_stats_only = true;
            }
        }
    }

    if target_session != sender_id && target_session.get_node_id() != local_node_id {
        if let Some(app) = server.s2s_manager().application() {
            let reply = app
                .user_stats()
                .dispatch_request(
                    target_session.get_node_id(),
                    sender_raw,
                    target_session_raw,
                    effective_stats_only,
                    server_id.clone(),
                )
                .await;
            match reply {
                Ok(r) if r.found && !r.payload.is_empty() => {
                    let proto = match crate::mumble_proto::UserStats::decode(r.payload.as_ref()) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                target = target_session_raw,
                                "user_stats: owner returned undecodable payload",
                            );
                            return Ok(());
                        }
                    };
                    let user_stats: UserStats = proto.into();
                    let outbound: Message = user_stats.into();
                    sender.write_proto_message(&outbound).await?;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        target = target_session_raw,
                        "user_stats: dispatch_request failed",
                    );
                }
            }
        } else {
            tracing::trace!(
                target = target_session_raw,
                "cross-owner UserStats dropped: ApplicationLayer not attached",
            );
        }
        return Ok(());
    }

    let target = if target_session != sender_id {
        match server
            .get_clients()
            .get_client_in_server(&server_id, target_session)
            .await
        {
            Some(c) => c,
            None => return Ok(()),
        }
    } else {
        sender.clone()
    };

    let user_stats = build_user_stats_payload(&target, effective_stats_only).await;
    let reply: Message = user_stats.into();
    sender.write_proto_message(&reply).await?;
    Ok(())
}

/// Build the `encoder::UserStats` reply for `target`. Used by both the
/// same-node fast path and the cross-node responder. The caller is
/// responsible for transporting the result back to the moderator
/// (encoded protobuf for cross-node, `Message::UserStats` write for the
/// local path).
async fn build_user_stats_payload(target: &Arc<Box<Client>>, stats_only: bool) -> UserStats {
    let stats = *target.write_stats().await;
    let local_state = target.read_local_state();
    let local = local_state.as_ref();

    let now = chrono::Utc::now();
    let login_time = target.get_login_time();
    let onlinesecs = (now - login_time).num_seconds().max(0) as u32;
    let idlesecs = target.idle_duration().num_seconds().max(0) as u32;
    let bandwidth = average_bandwidth_bits_per_second(stats.total_volume(), onlinesecs);

    let version = target.protocol_version().map(|v| {
        crate::messages::encoder::Version {
            version: Some(v),
            release: local.and_then(|l| l.get_release().map(|s| s.to_owned())),
            os: local.and_then(|l| l.get_os_name().map(|s| s.to_owned())),
            os_version: local.and_then(|l| l.get_os_version().map(|s| s.to_owned())),
        }
        .into()
    });

    UserStats {
        session: Some(u32::from(target.get_session_id())),
        stats_only: Some(stats_only),
        certificates: if stats_only {
            Vec::new()
        } else {
            target.get_certificate_chain().to_vec()
        },
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
        address: Some(target.get_real_ip_address()),
        bandwidth: Some(bandwidth),
        onlinesecs: Some(onlinesecs),
        idlesecs: Some(idlesecs),
        strong_certificate: Some(target.is_verified()),
        opus: Some(true),
    }
}

fn average_bandwidth_bits_per_second(total_bytes: u64, onlinesecs: u32) -> u32 {
    let elapsed = u64::from(onlinesecs.max(1));
    total_bytes
        .saturating_mul(8)
        .checked_div(elapsed)
        .unwrap_or(0)
        .min(u64::from(u32::MAX)) as u32
}

/// Owner-side responder for the cross-node UserStats RPC.
///
/// Looks up the target client in the local repository and, if found,
/// builds and protobuf-encodes a `MumbleProto.UserStats` message that
/// the originator forwards verbatim to the moderator.
pub struct ServerUserStatsResponder {
    server: std::sync::Weak<Box<Server>>,
}

impl ServerUserStatsResponder {
    pub fn new(server: std::sync::Weak<Box<Server>>) -> Arc<Self> {
        Arc::new(Self { server })
    }
}

#[async_trait]
impl UserStatsResponder for ServerUserStatsResponder {
    async fn respond(
        &self,
        _from: NodeIdentifier,
        request: UserStatsRequest,
    ) -> UserStatsApplyOutcome {
        let Some(server) = self.server.upgrade() else {
            return UserStatsApplyOutcome {
                found: false,
                payload: Bytes::new(),
            };
        };
        let target_id = crate::client::client_session_identifier::ClientSessionIdentifier::from(
            request.target_session,
        );
        let server_id = if request.server_id.is_empty() {
            crate::types::default_server_id()
        } else {
            request.server_id.clone()
        };
        // Owner-only RPC: target should belong to this node. If for some
        // reason it doesn't (replication / lookup race), reply not_found.
        if target_id.get_node_id() != server.get_clients().local_node_id() {
            return UserStatsApplyOutcome {
                found: false,
                payload: Bytes::new(),
            };
        }
        let Some(target) = server
            .get_clients()
            .get_client_in_server(&server_id, target_id)
            .await
        else {
            return UserStatsApplyOutcome {
                found: false,
                payload: Bytes::new(),
            };
        };
        let mut stats_only = request.stats_only;
        let actor_id = crate::client::client_session_identifier::ClientSessionIdentifier::from(
            request.actor_session,
        );
        if actor_id != target_id {
            let Some(actor) = server
                .get_clients()
                .get_client_in_server(&server_id, actor_id)
                .await
            else {
                return UserStatsApplyOutcome {
                    found: false,
                    payload: Bytes::new(),
                };
            };
            let target_channel = target.get_current_channel_id();
            let root_perms =
                crate::client::acl::compute_permissions_for_client(&server, &actor, 0).await;
            if !root_perms.contains(crate::acl::ACLPermissions::Ban) {
                let target_channel_perms = crate::client::acl::compute_permissions_for_client(
                    &server,
                    &actor,
                    target_channel,
                )
                .await;
                if !target_channel_perms.contains(crate::acl::ACLPermissions::Enter) {
                    return UserStatsApplyOutcome {
                        found: false,
                        payload: Bytes::new(),
                    };
                }
                stats_only = true;
            }
        }
        let user_stats = build_user_stats_payload(&target, stats_only).await;
        let proto: crate::mumble_proto::UserStats = user_stats.into();
        let mut buf = BytesMut::with_capacity(proto.encoded_len());
        if let Err(e) = proto.encode(&mut buf) {
            tracing::warn!(error=%e, "user_stats: failed to encode reply payload");
            return UserStatsApplyOutcome {
                found: false,
                payload: Bytes::new(),
            };
        }
        UserStatsApplyOutcome {
            found: true,
            payload: buf.freeze(),
        }
    }
}
