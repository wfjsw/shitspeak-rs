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
    let local_node_id = server.get_clients().local_node_id();

    // ── Cross-node target ────────────────────────────────────────────────
    // The target lives on a different node — its real-time stats (TCP/UDP
    // counters, ping windows, login_time, etc) are *not* replicated, so
    // the originator can't build the reply locally. Round-trip through the
    // L3 UserStats RPC: dispatch a request to the owner, await an encoded
    // `MumbleProto.UserStats` payload, forward it to the moderator's TLS
    // stream as-is.
    if let Some(target_session) = msg.session {
        let target_id =
            crate::client::client_session_identifier::ClientSessionIdentifier::from(target_session);
        if target_id != sender_id && target_id.get_node_id() != local_node_id {
            if let Some(app) = server.s2s_manager().application() {
                let reply = app
                    .user_stats()
                    .dispatch_request(
                        target_id.get_node_id(),
                        u32::from(sender_id),
                        target_session,
                        msg.stats_only.unwrap_or(false),
                    )
                    .await;
                match reply {
                    Ok(r) if r.found && !r.payload.is_empty() => {
                        let proto = match crate::mumble_proto::UserStats::decode(r.payload.as_ref())
                        {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    target = target_session,
                                    "user_stats: owner returned undecodable payload",
                                );
                                return Ok(());
                            }
                        };
                        let user_stats: UserStats = proto.into();
                        let outbound: Message = user_stats.into();
                        sender.write_proto_message(&outbound).await?;
                    }
                    Ok(_) => {
                        // not_found / empty payload: target gone on the
                        // owner side; mirror local-only "drop silently".
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            target = target_session,
                            "user_stats: dispatch_request failed",
                        );
                    }
                }
            } else {
                tracing::trace!(
                    target = target_session,
                    "cross-owner UserStats dropped: ApplicationLayer not attached",
                );
            }
            return Ok(());
        }
    }

    // ── Same-node target / self-stats ─────────────────────────────────────
    // Look up the target locally.
    let target = match msg.session {
        Some(session_id) if session_id != u32::from(sender_id) => {
            let target_id =
                crate::client::client_session_identifier::ClientSessionIdentifier::from(session_id);
            match server.get_clients().get_client(target_id).await {
                Some(c) => c,
                None => return Ok(()),
            }
        }
        _ => sender.clone(),
    };

    let user_stats = build_user_stats_payload(&target, msg.stats_only.unwrap_or(false)).await;
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
    let onlinesecs = (now - login_time).num_seconds() as u32;

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
        address: Some(target.get_real_ip_address()),
        bandwidth: Some(0), // TODO: bandwidth tracking
        onlinesecs: Some(onlinesecs),
        idlesecs: Some(0), // TODO: idle tracking
        strong_certificate: Some(target.is_verified()),
        opus: Some(true),
    }
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
        // Owner-only RPC: target should belong to this node. If for some
        // reason it doesn't (replication / lookup race), reply not_found.
        if target_id.get_node_id() != server.get_clients().local_node_id() {
            return UserStatsApplyOutcome {
                found: false,
                payload: Bytes::new(),
            };
        }
        let Some(target) = server.get_clients().get_client(target_id).await else {
            return UserStatsApplyOutcome {
                found: false,
                payload: Bytes::new(),
            };
        };
        let user_stats = build_user_stats_payload(&target, request.stats_only).await;
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
