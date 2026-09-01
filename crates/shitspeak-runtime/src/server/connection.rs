#[cfg(test)]
use std::collections::HashMap;
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tracing::Instrument;

#[cfg(test)]
use crate::channel_handler::{
    ChannelPermissionShadow, ChannelReplayError, replay_channel_log_gap_with_permission_shadow,
};
use crate::channel_handler::{ChannelTreeShadow, SessionChannelShadow};
#[cfg(test)]
use crate::client::state_log::{
    ClientStateBroadcastPayload, ClientStateLogEntry, ClientStateOperation,
};
use crate::client::{
    AsyncMessageHandlerExt, Client, ClientOutboundMessage,
    client_session_identifier::ClientSessionIdentifier, visibility::UserVisibilityState,
};
use crate::errors::{HandleIncomingConnectionError, MessageHandlerError, WriteProtoMessageError};
use crate::proxy_protocol::consume_proxy_protocol_connection_info;
use crate::types::default_server_id;
use shitspeak_messages::messages::encoder::Version;
use shitspeak_messages::messages::{Message, WriteMessageExt};
#[cfg(test)]
use shitspeak_state::ChannelOperation;

use super::Server;
use super::client_projection::ClientProjectionState;
use super::client_projection_pool::ClientProjectionRegistration;
use super::entrypoints::normalize_sni_name;
use super::extensions::{ALPN_MUMBLE, AlpnConnectionInfo};

#[cfg(test)]
type ClientLogReceiver = tokio::sync::broadcast::Receiver<Arc<ClientStateBroadcastPayload>>;
#[cfg(test)]
type ChannelLogReceiver = tokio::sync::broadcast::Receiver<Arc<ChannelOperation>>;

const CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT: usize = 64;
const CLIENT_VOICE_TCP_QUEUE_DRAIN_LIMIT: usize = 64;
const MIN_AUTHENTICATE_TIMEOUT_MS: u64 = 1;
const PRE_AUTH_DEFERRED_MESSAGE_LIMIT: usize = 32;

fn is_pre_auth_passthrough_message(message: &Message) -> bool {
    matches!(message, Message::Ping(_))
}

fn is_pre_auth_dropped_message(message: &Message) -> bool {
    matches!(message, Message::UDPTunnel(_))
}

fn is_realtime_client_message(message: &Message) -> bool {
    matches!(message, Message::Ping(_) | Message::UDPTunnel(_))
}

/// Classify a message into an optional rate-limit tier (see
/// [`crate::rate_limits`] `MESSAGE_TIER_*`). Query messages deliberately
/// bypass client-message rate limiting; RequestBlob is instead serialized by
/// its own per-client FIFO queue.
fn message_rate_tier(message: &Message) -> Option<usize> {
    match message {
        Message::PermissionQuery(_)
        | Message::QueryUsers(_)
        | Message::ContextAction(_)
        | Message::VoiceTarget(_)
        | Message::UserStats(_)
        | Message::RequestBlob(_) => None,
        Message::TextMessage(_) => Some(crate::rate_limits::MESSAGE_TIER_TEXT),
        Message::Ping(_) | Message::UDPTunnel(_) | _ => {
            Some(crate::rate_limits::MESSAGE_TIER_STATE)
        }
    }
}

fn authenticate_timeout_duration(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.max(MIN_AUTHENTICATE_TIMEOUT_MS))
}

fn map_handler_result(
    session_id: ClientSessionIdentifier,
    result: Result<(), MessageHandlerError>,
) -> Result<(), HandleIncomingConnectionError> {
    match result {
        Ok(()) => Ok(()),
        Err(MessageHandlerError::AuthRejection(rejection)) => {
            tracing::info!(
                session = u32::from(session_id),
                reason = rejection.reason(),
                "closing connection after auth rejection",
            );
            Err(HandleIncomingConnectionError::AuthRejected(rejection))
        }
        Err(err) => Err(HandleIncomingConnectionError::MessageHandlerFailed(err)),
    }
}

#[cfg(test)]
fn map_channel_replay_error(error: ChannelReplayError) -> HandleIncomingConnectionError {
    match error {
        ChannelReplayError::ClientWriteFailed(error) => {
            HandleIncomingConnectionError::ClientWriteFailed(error)
        }
    }
}

#[cfg(test)]
pub(super) async fn activate_client_subscriptions(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    _client_session_id: ClientSessionIdentifier,
    client_log_rx: &mut Option<ClientLogReceiver>,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_permission_shadow: &mut ChannelPermissionShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> Result<(), HandleIncomingConnectionError> {
    if !client.is_authenticated() || client_log_rx.is_some() {
        return Ok(());
    }
    let server_id = client.server_id();
    let client_session_id = client.get_session_id();

    let post_auth_baseline = client.take_post_auth_baseline();
    let staged_channel_subscription = client.take_channel_state_subscription();
    let channel_snapshot_version = staged_channel_subscription
        .as_ref()
        .map(|(version, _)| *version)
        .unwrap_or_else(|| server.channels.current_version_in_server(&server_id));
    client
        .set_last_channel_version(channel_snapshot_version)
        .await;
    channel_tree_shadow.clear();
    channel_permission_shadow.clear();
    if let Some(baseline) = post_auth_baseline {
        let (staged_session_shadow, staged_channel_tree_shadow, staged_user_visibility, _) =
            baseline.into_parts();
        session_channel_shadow.clear();
        session_channel_shadow.extend(staged_session_shadow);
        channel_tree_shadow.extend(staged_channel_tree_shadow);
        *user_visibility = staged_user_visibility;
    } else {
        tracing::warn!(
            server_id,
            session = u32::from(client_session_id),
            "post-auth baseline missing; rebuilding subscription shadows from repositories"
        );
        let channels = server.channels.ordered_snapshot_in_server(&server_id);
        if server.get_hide_channels_without_traverse() {
            for channel in channels.iter() {
                if crate::channel_handler::can_view_channel_with_ancestors(
                    server, client, channel.id,
                )
                .await
                {
                    channel_tree_shadow.insert(channel.id);
                }
            }
        } else {
            channel_tree_shadow.extend(channels.iter().map(|channel| channel.id));
        }
        if crate::client::visibility::user_filtering_enabled(server, client) {
            crate::client::visibility::initialize(
                server,
                client,
                user_visibility,
                session_channel_shadow,
            )
            .await;
        } else {
            session_channel_shadow.extend(
                server
                    .clients
                    .get_all_clients_in_server(&server_id)
                    .await
                    .into_iter()
                    .filter(|client| {
                        client.is_authenticated() && client.is_published() && !client.is_invisible()
                    })
                    .map(|client| (client.get_session_id(), client.get_current_channel_id())),
            );
        }
    }

    server
        .clients
        .publish_client_in_server(&server_id, client_session_id)
        .await;

    *client_log_rx = Some(
        client
            .take_client_state_subscription()
            .unwrap_or_else(|| server.clients.subscribe()),
    );
    *channel_log_rx = Some(
        staged_channel_subscription
            .map(|(_, rx)| rx)
            .unwrap_or_else(|| server.channels.subscribe()),
    );

    replay_client_log_entries_since(
        server,
        client,
        channel_tree_shadow,
        channel_permission_shadow,
        session_channel_shadow,
        user_visibility,
        &server_id,
        client_session_id,
        client.get_last_client_versions().await,
    )
    .await?;
    crate::client::handlers::spawn_staged_session_blob_resolution(
        Arc::clone(server),
        Arc::clone(client),
    );
    Ok(())
}

pub(super) async fn activate_client_projection(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    registration: &mut Option<ClientProjectionRegistration>,
) -> Result<(), HandleIncomingConnectionError> {
    if !client.is_authenticated() || registration.is_some() {
        return Ok(());
    }

    let server_id = client.server_id();
    let client_session_id = client.get_session_id();
    let staged_channel_subscription = client.take_channel_state_subscription();
    let staged_channel_version = staged_channel_subscription
        .as_ref()
        .map(|(version, _)| *version)
        .unwrap_or_else(|| server.channels.current_version_in_server(&server_id));
    let (staged_client_versions, staged_client_epochs) = client.get_last_client_cursors().await;
    // Native clients no longer retain their own log receivers after auth. The
    // shard's registration hook catches up from these exact snapshot cursors.
    drop(staged_channel_subscription);
    drop(client.take_client_state_subscription());

    let (baseline, last_client_versions, last_client_epochs, channel_snapshot_version) =
        if let Some(baseline) = client.take_post_auth_baseline() {
            (
                baseline,
                staged_client_versions,
                staged_client_epochs,
                staged_channel_version,
            )
        } else {
            tracing::warn!(
                server_id,
                session = u32::from(client_session_id),
                "post-auth baseline missing; atomically recapturing projection snapshots"
            );
            let (snapshot_clients, snapshot_versions, snapshot_epochs, snapshot_client_rx) = server
                .clients
                .published_snapshot_with_versions_and_subscription_in_server(&server_id)
                .await;
            let (channels, snapshot_channel_version, snapshot_channel_rx) = server
                .channels
                .snapshot_with_version_and_subscription_in_server(&server_id);
            drop(snapshot_client_rx);
            drop(snapshot_channel_rx);
            let mut channel_tree_shadow = ChannelTreeShadow::default();
            let mut session_channel_shadow = SessionChannelShadow::new();
            let mut user_visibility = UserVisibilityState::default();
            let visibility_generation = server.visibility_generation();
            if server.get_hide_channels_without_traverse() {
                for channel in channels.iter() {
                    if crate::channel_handler::can_view_channel_with_ancestors(
                        server, client, channel.id,
                    )
                    .await
                    {
                        channel_tree_shadow.insert(channel.id);
                    }
                }
            } else {
                channel_tree_shadow.extend(channels.iter().map(|channel| channel.id));
            }
            if crate::client::visibility::user_filtering_enabled(server, client) {
                crate::client::visibility::initialize(
                    server,
                    client,
                    &mut user_visibility,
                    &mut session_channel_shadow,
                )
                .await;
            } else {
                session_channel_shadow.extend(
                    snapshot_clients
                        .into_iter()
                        .filter(|client| {
                            client.is_authenticated()
                                && client.is_published()
                                && !client.is_invisible()
                        })
                        .map(|client| (client.get_session_id(), client.get_current_channel_id())),
                );
            }
            (
                crate::client::PostAuthBaseline::with_user_visibility(
                    session_channel_shadow,
                    channel_tree_shadow,
                    user_visibility,
                    visibility_generation,
                ),
                snapshot_versions,
                snapshot_epochs,
                snapshot_channel_version,
            )
        };

    let state = ClientProjectionState::from_post_auth_baseline(
        Arc::downgrade(server),
        Arc::clone(client),
        baseline,
        last_client_versions,
        last_client_epochs,
        channel_snapshot_version,
    );

    // Publish before the potentially expensive catch-up hook. Otherwise a
    // burst of authenticated clients serializes publication behind growing
    // per-client replay work and leaves users invisible for an extended time.
    server
        .clients
        .publish_client_in_server(&server_id, client_session_id)
        .await;
    let projection_registration = server
        .client_projection_pool()
        .register(state)
        .await
        .map_err(|error| {
            HandleIncomingConnectionError::IOError(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                error,
            ))
        })?;
    *registration = Some(projection_registration);
    crate::client::handlers::spawn_staged_session_blob_resolution(
        Arc::clone(server),
        Arc::clone(client),
    );
    Ok(())
}

#[cfg(test)]
async fn replay_client_log_entries_since(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_permission_shadow: &mut ChannelPermissionShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    server_id: &str,
    client_session_id: ClientSessionIdentifier,
    last_seen: HashMap<u16, u64>,
) -> Result<(), HandleIncomingConnectionError> {
    let last_epochs = client.get_last_client_epochs().await;
    let catch_up = server
        .clients
        .replay_entries_since_in_server_for_client(
            server_id,
            &last_seen,
            &last_epochs,
            client.get_session_id(),
            client.client_instance_id(),
        )
        .await;
    let (rebases, missed, target_versions, target_epochs) = catch_up.into_parts();

    let mut out = Vec::new();
    for rebase in rebases {
        let (origin, _version, _epoch, entries) = rebase.into_parts();
        append_client_origin_reset_messages(
            server,
            client,
            user_visibility,
            session_channel_shadow,
            server_id,
            origin,
            &mut out,
        )
        .await;
        for entry in entries {
            if should_skip_client_add_entry(
                &entry.op,
                client.get_session_id(),
                client.client_instance_id(),
                session_channel_shadow,
            ) {
                continue;
            }
            append_client_log_entry_messages(
                server,
                client,
                client_session_id,
                channel_tree_shadow,
                channel_permission_shadow,
                user_visibility,
                session_channel_shadow,
                server_id,
                &entry,
                &mut out,
            )
            .await?;
        }
    }
    for entry in missed {
        if should_skip_client_add_entry(
            &entry.op,
            client.get_session_id(),
            client.client_instance_id(),
            session_channel_shadow,
        ) {
            continue;
        }
        append_client_log_entry_messages(
            server,
            client,
            client_session_id,
            channel_tree_shadow,
            channel_permission_shadow,
            user_visibility,
            session_channel_shadow,
            server_id,
            &entry,
            &mut out,
        )
        .await?;
    }
    client
        .write_proto_message_batch(&out)
        .await
        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
    client
        .set_last_client_cursors(target_versions, target_epochs)
        .await;
    Ok(())
}

async fn finish_handler_result(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    projection_registration: &mut Option<ClientProjectionRegistration>,
    result: Result<(), MessageHandlerError>,
) -> Result<(), HandleIncomingConnectionError> {
    if matches!(
        result,
        Err(MessageHandlerError::AuthRejection(_) | MessageHandlerError::BannedConnection)
    ) {
        let _ = client.force_disconnect().await;
    }
    map_handler_result(client_session_id, result)?;
    activate_client_projection(server, client, projection_registration).await
}

async fn finish_normal_client_message(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    projection_registration: &mut Option<ClientProjectionRegistration>,
    message: Message,
) -> Result<(), HandleIncomingConnectionError> {
    let result = client.handle_message(server, message).await;
    finish_handler_result(
        server,
        client,
        client.get_session_id(),
        projection_registration,
        result,
    )
    .await?;
    client.touch_activity();
    Ok(())
}

async fn finish_deferred_client_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    projection_registration: &mut Option<ClientProjectionRegistration>,
    messages: &mut VecDeque<Message>,
) -> Result<(), HandleIncomingConnectionError> {
    while let Some(message) = messages.pop_front() {
        finish_normal_client_message(server, client, projection_registration, message).await?;
    }
    Ok(())
}

async fn continue_deferred_client_messages(
    handler_tasks: &mut JoinSet<Result<(), MessageHandlerError>>,
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    projection_registration: &mut Option<ClientProjectionRegistration>,
    messages: &mut VecDeque<Message>,
    pre_auth_handler_in_flight: &mut bool,
) -> Result<(), HandleIncomingConnectionError> {
    if messages.is_empty() || *pre_auth_handler_in_flight {
        return Ok(());
    }

    if !client.is_authenticated() {
        if let Some(message) = messages.pop_front() {
            spawn_client_message_handler(handler_tasks, server, client, message);
            *pre_auth_handler_in_flight = true;
        }
        return Ok(());
    }

    finish_deferred_client_messages(server, client, projection_registration, messages).await
}

async fn finish_pre_auth_passthrough_message(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    message: Message,
) -> Result<(), HandleIncomingConnectionError> {
    let result = client.handle_message(server, message).await;
    map_handler_result(client.get_session_id(), result)?;
    client.touch_activity();
    Ok(())
}

fn spawn_client_message_handler(
    handler_tasks: &mut JoinSet<Result<(), MessageHandlerError>>,
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    message: Message,
) {
    // Per-client, per-type leaky-bucket rate limit: drop messages beyond the
    // (generous) budget for their tier instead of spawning unbounded handler
    // tasks. Real clients stay far below the limits; floods get silently
    // truncated rather than desynchronizing the connection by a forced
    // disconnect.
    if let Some(tier) = message_rate_tier(&message) {
        let session_id = u32::from(client.get_session_id());
        debug_assert!(tier < crate::rate_limits::MESSAGE_TIER_COUNT);
        if !server.client_message_rate_limiters()[tier].try_acquire(&session_id) {
            tracing::debug!(
                session = session_id,
                tier,
                "client message rate limit exceeded, dropping message"
            );
            return;
        }
    }
    let handler_server = Arc::clone(server);
    let handler_client = Arc::clone(client);
    handler_tasks.spawn(async move {
        handler_client
            .handle_message(&handler_server, message)
            .await
    });
}

pub(super) fn sorted_channel_ids(channel_ids: &HashSet<u32>) -> Vec<u32> {
    let mut channel_ids: Vec<_> = channel_ids.iter().copied().collect();
    channel_ids.sort_unstable();
    channel_ids
}

#[cfg(test)]
async fn append_client_log_entry_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_permission_shadow: &mut ChannelPermissionShadow,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    _server_id: &str,
    entry: &ClientStateLogEntry,
    out: &mut Vec<Message>,
) -> Result<(), HandleIncomingConnectionError> {
    if let Some(dep) = entry.channel_version_dep {
        let last_ch = client.get_last_channel_version().await;
        if last_ch < dep {
            client
                .write_proto_message_batch(out)
                .await
                .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
            out.clear();
            replay_channel_log_gap_with_permission_shadow(
                server,
                client,
                &server.channels,
                channel_tree_shadow,
                session_channel_shadow,
                user_visibility,
                channel_permission_shadow,
                client_session_id,
                last_ch,
                dep + 1,
            )
            .await
            .map_err(map_channel_replay_error)?;
        }
    }

    let messages = crate::channel_handler::project_client_log_entry_transition(
        server,
        client,
        channel_tree_shadow,
        user_visibility,
        session_channel_shadow,
        entry,
    )
    .await;
    out.extend(
        crate::channel_handler::suppress_known_projected_permission_messages(
            messages,
            channel_permission_shadow,
        ),
    );
    Ok(())
}

async fn drain_outbound_message_queue(
    client: &Arc<Box<Client>>,
    first: ClientOutboundMessage,
    rx: &mut tokio::sync::mpsc::Receiver<ClientOutboundMessage>,
) -> Result<(), WriteProtoMessageError> {
    let mut messages = Vec::new();
    push_outbound_message(first, &mut messages);
    for _ in 1..CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT {
        match rx.try_recv() {
            Ok(message) => push_outbound_message(message, &mut messages),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    client.write_proto_message_batch_direct(&messages).await
}

async fn drain_voice_tcp_queue(
    client: &Arc<Box<Client>>,
    first: bytes::Bytes,
    rx: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>,
) -> Result<(), WriteProtoMessageError> {
    let mut frames = Vec::with_capacity(CLIENT_VOICE_TCP_QUEUE_DRAIN_LIMIT);
    frames.push(first);
    for _ in 1..CLIENT_VOICE_TCP_QUEUE_DRAIN_LIMIT {
        match rx.try_recv() {
            Ok(raw) => frames.push(raw),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    client.write_udp_tunnel_batch_direct(&frames).await
}

fn push_outbound_message(message: ClientOutboundMessage, out: &mut Vec<Message>) {
    match message {
        ClientOutboundMessage::Single(message) => out.push(message),
        ClientOutboundMessage::Batch(messages) => out.extend(messages),
    }
}

fn spawn_native_client_writer_task(
    client: &Arc<Box<Client>>,
) -> Option<tokio::task::JoinHandle<Result<(), WriteProtoMessageError>>> {
    let span = client.tracing_span();
    let server_span = client.server_tracing_span();
    let mut rx = match client.take_outbound_message_rx() {
        Some(rx) => rx,
        None => {
            server_span.in_scope(|| {
                span.in_scope(|| {
                    tracing::warn!(
                        session = u32::from(client.get_session_id()),
                        "native client writer task already spawned"
                    );
                });
            });
            return None;
        }
    };
    let mut voice_rx = match client.take_voice_tcp_rx() {
        Some(rx) => rx,
        None => {
            server_span.in_scope(|| {
                span.in_scope(|| {
                    tracing::warn!(
                        session = u32::from(client.get_session_id()),
                        "native client voice TCP queue already claimed"
                    );
                });
            });
            return None;
        }
    };
    let weak_client = Arc::downgrade(client);
    Some(tokio::spawn(
        async move {
            let mut outbound_closed = false;
            let mut voice_closed = false;
            loop {
                let Some(client) = weak_client.upgrade() else {
                    break;
                };

                if !voice_closed {
                    match voice_rx.try_recv() {
                        Ok(raw) => {
                            drain_voice_tcp_queue(&client, raw, &mut voice_rx).await?;
                            continue;
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                            voice_closed = true;
                        }
                    }
                }

                if outbound_closed && voice_closed {
                    break;
                }

                tokio::select! {
                    biased;
                    raw = voice_rx.recv(), if !voice_closed => {
                        match raw {
                            Some(raw) => drain_voice_tcp_queue(&client, raw, &mut voice_rx).await?,
                            None => voice_closed = true,
                        }
                    }
                    message = rx.recv(), if !outbound_closed => {
                        match message {
                            Some(message) => drain_outbound_message_queue(&client, message, &mut rx).await?,
                            None => outbound_closed = true,
                        }
                    }
                }
            }
            Ok(())
        }
        .instrument(span)
        .instrument(server_span),
    ))
}

#[cfg(test)]
async fn advance_client_log_vector_if_out_of_scope(
    client: &Arc<Box<Client>>,
    client_server_id: &str,
    broadcast: &ClientStateBroadcastPayload,
) -> bool {
    let entry = &broadcast.entry;
    if entry.op.server_id() == client_server_id {
        return false;
    }

    // Client log versions are global per origin, even though the messages
    // projected onto a connection are scoped to one virtual server. Consume
    // the origin's sequence position before dropping an out-of-scope entry so
    // a later in-scope entry does not try to replay already-pruned history.
    if let Some(&version) = broadcast.versions.get(&entry.node_id) {
        client
            .update_last_client_versions(&HashMap::from([(entry.node_id, version)]))
            .await;
    }
    true
}

#[cfg(test)]
fn take_origin_sessions_from_shadow(
    shadow: &mut SessionChannelShadow,
    origin: u16,
) -> Vec<ClientSessionIdentifier> {
    let sessions = shadow
        .iter()
        .map(|(session, _)| session)
        .filter(|session| session.get_node_id() == origin)
        .collect::<Vec<_>>();
    for session in &sessions {
        shadow.remove(session);
    }
    sessions
}

#[cfg(test)]
async fn append_client_origin_reset_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    client_server_id: &str,
    origin: u16,
    out: &mut Vec<Message>,
) {
    let viewer_session = client.get_session_id();
    let viewer_old_channel = session_channel_shadow.get(&viewer_session).copied();
    let sessions = take_origin_sessions_from_shadow(session_channel_shadow, origin);
    for session in sessions {
        if session == viewer_session {
            session_channel_shadow.insert(
                session,
                viewer_old_channel.unwrap_or_else(|| client.get_current_channel_id()),
            );
            continue;
        }
        let removal: Message = shitspeak_messages::messages::encoder::UserRemove {
            session: u32::from(session),
            actor: None,
            reason: None,
            ban: Some(false),
            ban_certificate: None,
            ban_ip: None,
        }
        .into();
        out.extend(
            crate::client::visibility::project_message_with_shadow(
                server,
                client,
                user_visibility,
                session_channel_shadow,
                client_server_id,
                &removal,
            )
            .await,
        );
    }
}

#[cfg(test)]
async fn apply_client_snapshot_end_vector(client: &Arc<Box<Client>>, versions: &HashMap<u16, u64>) {
    client.update_last_client_versions(versions).await;
}

#[cfg(test)]
fn should_skip_client_add_entry(
    op: &ClientStateOperation,
    viewer_session_id: ClientSessionIdentifier,
    viewer_client_instance_id: crate::client::ClientInstanceId,
    session_channel_shadow: &SessionChannelShadow,
) -> bool {
    matches!(
        op,
        ClientStateOperation::AddClient {
            session_id,
            client_instance_id,
            ..
        } if *session_id == viewer_session_id && *client_instance_id == viewer_client_instance_id
            || session_channel_shadow.contains_key(session_id)
    )
}

impl Server {
    pub async fn handle_incoming_connection(
        self: &Arc<Box<Self>>,
        tcp_stream: tokio::net::TcpStream,
        remote_addr: std::net::SocketAddr,
        provisional_server_id: String,
    ) -> Result<(), HandleIncomingConnectionError> {
        let server_span = tracing::info_span!("server", virtual_server_id = %provisional_server_id);
        self.handle_incoming_connection_in_server_span(
            tcp_stream,
            remote_addr,
            provisional_server_id,
            server_span.clone(),
        )
        .instrument(server_span)
        .await
    }

    async fn handle_incoming_connection_in_server_span(
        self: &Arc<Box<Self>>,
        mut tcp_stream: tokio::net::TcpStream,
        remote_addr: std::net::SocketAddr,
        provisional_server_id: String,
        server_span: tracing::Span,
    ) -> Result<(), HandleIncomingConnectionError> {
        // A dual-stack listener reports IPv4 clients as IPv4-mapped IPv6.
        // Keep logs, authenticator data, and AF_PACKET flow keys in the same
        // canonical endpoint form.
        let remote_addr = shitspeak_auth::canonical_socket_addr(remote_addr);
        tracing::info!(
            %remote_addr,
            provisional_server_id,
            "TCP connection established"
        );
        if let Err(error) = tcp_stream.set_nodelay(true) {
            tracing::debug!(
                %remote_addr,
                %error,
                "failed to enable TCP_NODELAY for native connection"
            );
        }
        let proxy_connection = if self
            .allowed_proxies
            .iter()
            .any(|proxy| proxy.contains(&remote_addr.ip()))
        {
            consume_proxy_protocol_connection_info(&mut tcp_stream).await?
        } else {
            None
        };
        let uses_proxy_protocol = proxy_connection.is_some();
        let proxy_server_address = uses_proxy_protocol.then_some(remote_addr);
        let client_addr = proxy_connection
            .and_then(|info| info.client_address())
            .map(|addr| {
                shitspeak_auth::canonical_socket_addr(SocketAddr::new(addr.ip(), addr.port()))
            })
            .unwrap_or(remote_addr);
        let real_ip = client_addr.ip();

        // ── Banned IP check ───────────────────────────────────────────────
        // Reject banned sources before spending resources on a TLS handshake.
        if self.get_bans().is_banned(real_ip).await {
            tracing::info!(
                %remote_addr,
                %real_ip,
                "connection from banned IP closed before TLS handshake"
            );
            return Ok(());
        }
        // ASN bans are derived from the effective source IP, so enforce them
        // alongside IP bans before consuming TLS-handshake resources. Avoid
        // GeoIP work entirely unless an active ASN criterion exists.
        if self.get_bans().has_active_asn_bans()
            && self
                .lookup_ip_geo_metadata(real_ip)
                .await
                .and_then(|metadata| metadata.asn())
                .is_some_and(|asn| self.get_bans().is_asn_banned(asn))
        {
            tracing::info!(
                %remote_addr,
                %real_ip,
                "connection from banned ASN closed before TLS handshake"
            );
            return Ok(());
        }

        let local_addr = shitspeak_auth::canonical_socket_addr(tcp_stream.local_addr()?);
        tracing::info!(
            %remote_addr,
            %client_addr,
            %local_addr,
            uses_proxy_protocol,
            "TLS handshake starting"
        );
        let tls_acceptor = self.tls_acceptor.read().clone();
        // A slow/failed TLS handshake must not hold a connection slot (and a
        // task) indefinitely: cap ClientHello capture and the TLS handshake
        // together with one deadline.
        let (tls_stream, mut tls_fingerprints) = tokio::time::timeout(
            crate::rate_limits::TLS_HANDSHAKE_TIMEOUT,
            crate::tls_fingerprint::accept_tls_with_fingerprints(tcp_stream, &tls_acceptor),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
        })??;
        // Packet capture observes the physical TCP peer, not the address
        // asserted by a PROXY-protocol header. Never attribute the proxy's
        // TCP traits to the logical proxied client.
        if !uses_proxy_protocol
            && let Some(metadata) = self.tcp_packet_metadata(remote_addr, local_addr).await
        {
            tls_fingerprints.ja4t = Some(metadata.ja4t().to_owned());
            tls_fingerprints.ja4l = metadata.ja4l().map(ToOwned::to_owned);
        }
        tls_fingerprints.ja4x = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .and_then(|certificate| {
                crate::tls_fingerprint::ja4x_from_certificate(certificate.as_ref())
            });
        // Certificate hashes are rejected by the Rustls verifier during the
        // handshake. The JA4 fingerprint is available once ClientHello
        // capture completes, so reject that identity criterion before the
        // stream is routed or a native client is allocated.
        if self
            .get_bans()
            .is_identity_banned(None, tls_fingerprints.ja4.as_deref())
        {
            tracing::info!(
                %remote_addr,
                %real_ip,
                tls_ja4 = ?tls_fingerprints.ja4,
                "connection from banned TLS JA4 fingerprint closed after TLS handshake"
            );
            return Ok(());
        }
        let server_id = self.resolve_tls_server_id(&provisional_server_id, local_addr, &tls_stream);
        server_span.record("virtual_server_id", server_id.as_str());
        tracing::info!(
            %remote_addr,
            %client_addr,
            %local_addr,
            alpn = ?tls_stream.get_ref().1.alpn_protocol().map(String::from_utf8_lossy),
            tls_ja3 = ?tls_fingerprints.ja3,
            tls_ja4 = ?tls_fingerprints.ja4,
            tls_ja4t = ?tls_fingerprints.ja4t,
            tls_ja4x = ?tls_fingerprints.ja4x,
            tls_ja4l = ?tls_fingerprints.ja4l,
            tls_sni = ?tls_fingerprints.sni,
            "TLS handshake completed"
        );
        let negotiated_alpn = tls_stream.get_ref().1.alpn_protocol().map(Vec::from);
        if let Some(protocol) = negotiated_alpn.as_deref() {
            if protocol == ALPN_MUMBLE {
                // Continue with the native Mumble path below.
            } else if self.extensions.handles_c2s_alpn_protocol(protocol) {
                let info = AlpnConnectionInfo::new(
                    real_ip,
                    client_addr,
                    local_addr,
                    server_id,
                    tls_fingerprints,
                    uses_proxy_protocol,
                );
                if let Some(handler) = self.extensions.handle_c2s_alpn_stream(
                    Arc::clone(self),
                    protocol,
                    tls_stream,
                    info,
                ) {
                    handler.await?;
                } else {
                    tracing::warn!(
                        protocol = %String::from_utf8_lossy(protocol),
                        "ALPN protocol was registered but no handler accepted the stream"
                    );
                }
                return Ok(());
            } else {
                tracing::warn!(
                    protocol = %String::from_utf8_lossy(protocol),
                    "unsupported ALPN protocol, closing connection"
                );
                return Ok(());
            }
        }

        self.handle_native_mumble_tls_connection(
            tls_stream,
            real_ip,
            client_addr,
            local_addr,
            server_id,
            server_span,
            tls_fingerprints,
            proxy_server_address,
            uses_proxy_protocol,
        )
        .await
    }

    fn resolve_tls_server_id(
        &self,
        provisional_server_id: &str,
        local_addr: SocketAddr,
        tls_stream: &TlsStream<TcpStream>,
    ) -> String {
        let entrypoints = self.entrypoints.read();
        if let Some(port_server_id) = entrypoints.server_id_by_port.get(&local_addr.port()) {
            return port_server_id.clone();
        }

        let (_, connection) = tls_stream.get_ref();
        if let Some(server_name) = connection.server_name() {
            let name = normalize_sni_name(server_name);
            if let Some(server_id) = entrypoints.server_id_by_sni.get(&name) {
                return server_id.clone();
            }
        }

        if provisional_server_id.is_empty() {
            default_server_id()
        } else {
            provisional_server_id.to_owned()
        }
    }

    async fn handle_native_mumble_tls_connection(
        self: &Arc<Box<Self>>,
        mut tls_stream: TlsStream<TcpStream>,
        real_ip: std::net::IpAddr,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        server_id: String,
        server_span: tracing::Span,
        tls_fingerprints: crate::tls_fingerprint::TlsFingerprints,
        proxy_server_address: Option<std::net::SocketAddr>,
        uses_proxy_protocol: bool,
    ) -> Result<(), HandleIncomingConnectionError> {
        let authenticate_timeout =
            authenticate_timeout_duration(self.read_config().authenticate_timeout_ms);
        // Send server version (these are startup-only, read once)
        let version = {
            let cfg = self.read_config();
            Version::for_server_with_release(
                cfg.send_version,
                cfg.send_build_info,
                cfg.send_os_info,
                cfg.server_protocol_version,
                crate::constants::release,
            )
        }; // cfg dropped here
        tls_stream.write_proto_message(&version.into()).await?;

        let client = self
            .clients
            .allocate_local_client_in_server_with_tracing_span(
                server_id,
                real_ip,
                remote_addr,
                None,
                local_addr,
                tls_stream,
                tls_fingerprints,
                proxy_server_address,
                uses_proxy_protocol,
                server_span,
            )
            .await;

        let client_span = client.tracing_span();
        let server_span = client.server_tracing_span();

        // Projection ownership moves to one stable shard after authentication.
        // Keeping this handle connection-local makes unregister automatic on
        // every exit path.
        let mut projection_registration: Option<ClientProjectionRegistration> = None;
        let mut writer_task = spawn_native_client_writer_task(&client);

        // Run the connection loop.  On any unrecoverable error, clean up
        // the client and return the error to the caller.
        let result: Result<(), HandleIncomingConnectionError> = async {
            let mut handler_tasks = JoinSet::new();
            let mut pre_auth_handler_in_flight = false;
            let mut deferred_pre_auth_messages = VecDeque::new();
            let mut authenticate_deadline = Box::pin(tokio::time::sleep(authenticate_timeout));

            loop {
                tokio::select! {
                    biased;

                    // ── Authenticate timeout ────────────────────────────────
                    _ = &mut authenticate_deadline, if !client.is_authenticated() => {
                        tracing::info!(
                            server_id = %client.server_id(),
                            session = u32::from(client.get_session_id()),
                            timeout_ms = authenticate_timeout.as_millis(),
                            "closing connection after authenticate timeout"
                        );
                        return Err(HandleIncomingConnectionError::AuthenticateTimeout(authenticate_timeout));
                    }

                    // ── Local disconnect request ─────────────────────────────
                    _ = client.disconnected() => {
                        tracing::debug!(
                            session = u32::from(client.get_session_id()),
                            "closing connection after local disconnect request"
                        );
                        return Ok(());
                    }

                    // ── Completed client message handler ─────────────────────
                    result = handler_tasks.join_next(), if !handler_tasks.is_empty() => {
                        let Some(result) = result else { continue };
                        pre_auth_handler_in_flight = false;
                        let result = result
                            .map_err(HandleIncomingConnectionError::MessageHandlerTaskFailed)?;
                        finish_handler_result(
                            self,
                            &client,
                            client.get_session_id(),
                            &mut projection_registration,
                            result,
                        )
                        .await?;
                        client.touch_activity();
                        continue_deferred_client_messages(
                            &mut handler_tasks,
                            self,
                            &client,
                            &mut projection_registration,
                            &mut deferred_pre_auth_messages,
                            &mut pre_auth_handler_in_flight,
                        )
                        .await?;
                    }

                    // ── Dedicated writer task completion ─────────────────────
                    result = async {
                        match writer_task.as_mut() {
                            Some(task) => task.await,
                            None => std::future::pending().await,
                        }
                    }, if writer_task.is_some() => {
                        writer_task = None;
                        match result {
                            Ok(Ok(())) => return Ok(()),
                            Ok(Err(err)) => return Err(HandleIncomingConnectionError::ClientWriteFailed(err)),
                            Err(err) => return Err(HandleIncomingConnectionError::ClientWriterTaskFailed(err)),
                        }
                    }

                    // ── Projection shard failure ────────────────────────────
                    _ = async {
                        match projection_registration.as_mut() {
                            Some(registration) => registration.failed().await,
                            None => std::future::pending().await,
                        }
                    }, if projection_registration.is_some() => {
                        return Err(HandleIncomingConnectionError::IOError(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "client projection shard stopped",
                        )));
                    }

                    // ── Deferred pre-auth message ───────────────────────────
                    _ = std::future::ready(()), if !pre_auth_handler_in_flight && !deferred_pre_auth_messages.is_empty() => {
                        continue_deferred_client_messages(
                            &mut handler_tasks,
                            self,
                            &client,
                            &mut projection_registration,
                            &mut deferred_pre_auth_messages,
                            &mut pre_auth_handler_in_flight,
                        )
                        .await?;
                    }

                    // ── Incoming message from this client ────────────────────
                    // Reads are never gated here: realtime messages (Ping,
                    // UDPTunnel voice-over-TCP) must flow even while handler
                    // tasks are backed up. The in-flight bound lives in the
                    // non-realtime branch below instead.
                    result = client.read_proto_message() => {
                        match result {
                            Ok(message) => {
                                if pre_auth_handler_in_flight {
                                    if is_pre_auth_dropped_message(&message) {
                                        if let Message::UDPTunnel(data) = &message {
                                            tracing::trace!(
                                                session = u32::from(client.get_session_id()),
                                                len = data.len(),
                                                "dropping UDPTunnel before authentication completed"
                                            );
                                        }
                                    } else if is_pre_auth_passthrough_message(&message) {
                                        finish_pre_auth_passthrough_message(self, &client, message).await?;
                                    } else if deferred_pre_auth_messages.len() < PRE_AUTH_DEFERRED_MESSAGE_LIMIT {
                                        deferred_pre_auth_messages.push_back(message);
                                    } else {
                                        return Err(HandleIncomingConnectionError::MessageHandlerFailed(
                                            MessageHandlerError::protocol_violation(
                                                "too many queued messages before authentication completed",
                                            ),
                                        ));
                                    }
                                } else if !client.is_authenticated()
                                    && is_pre_auth_dropped_message(&message)
                                {
                                    if let Message::UDPTunnel(data) = &message {
                                        tracing::trace!(
                                            session = u32::from(client.get_session_id()),
                                            len = data.len(),
                                            "dropping UDPTunnel before authentication completed"
                                        );
                                    }
                                } else if is_realtime_client_message(&message) {
                                    finish_normal_client_message(
                                        self,
                                        &client,
                                        &mut projection_registration,
                                        message,
                                    )
                                    .await?;
                                } else {
                                    // Bound in-flight non-realtime handler
                                    // tasks without stalling realtime traffic:
                                    // when the cap is reached, await one
                                    // completion before spawning the next.
                                    // (This briefly pauses *non-realtime*
                                    // processing; Ping/UDPTunnel are handled
                                    // in the realtime branch above and only
                                    // wait behind the short completion await.)
                                    if handler_tasks.len()
                                        >= crate::rate_limits::MAX_IN_FLIGHT_HANDLERS
                                    {
                                        if let Some(result) =
                                            handler_tasks.join_next().await
                                        {
                                            pre_auth_handler_in_flight = false;
                                            let result = result.map_err(
                                                HandleIncomingConnectionError::MessageHandlerTaskFailed,
                                            )?;
                                            finish_handler_result(
                                                self,
                                                &client,
                                                client.get_session_id(),
                                                &mut projection_registration,
                                                result,
                                            )
                                            .await?;
                                            client.touch_activity();
                                            continue_deferred_client_messages(
                                                &mut handler_tasks,
                                                self,
                                                &client,
                                                &mut projection_registration,
                                                &mut deferred_pre_auth_messages,
                                                &mut pre_auth_handler_in_flight,
                                            )
                                            .await?;
                                        }
                                    }
                                    let spawned_before_auth = !client.is_authenticated();
                                    spawn_client_message_handler(&mut handler_tasks, self, &client, message);
                                    if spawned_before_auth {
                                        // Version and Authenticate often arrive back-to-back in
                                        // one TCP read window. Keep pre-auth handlers ordered so
                                        // Authenticate sees the Version data before it builds the
                                        // authenticator auxiliary payload.
                                        pre_auth_handler_in_flight = true;
                                    }
                                }
                            }
                            Err(crate::errors::ReadProtoMessageError::UnknownMessageType(err)) => {
                                tracing::warn!(
                                    session = u32::from(client.get_session_id()),
                                    message_type = err.message_type,
                                    "client sent unknown message type; ignoring",
                                );
                                // Gracefully ignore unknown message types
                            }
                            Err(err) => return Err(HandleIncomingConnectionError::ReadProtoMessageError(err)),
                        }
                    }

                }
            }
        }
        .instrument(client_span.clone())
        .instrument(server_span.clone())
        .await;

        // Stop shard projection before repository removal. This also covers a
        // non-blocking writer-queue rejection, which signals disconnect and
        // otherwise reaches this point as a local (successful) shutdown.
        drop(projection_registration.take());
        if let Some(task) = writer_task.take() {
            task.abort();
            let _ = task.await;
        }
        if result.is_err() {
            let _ = client.force_disconnect().await;
        }
        async {
            let server_id = client.server_id();
            let old_channel_id = client.get_current_channel_id();
            self.clients
                .remove_client_instance_in_server(
                    &server_id,
                    client.get_session_id(),
                    client.client_instance_id(),
                )
                .await;
            crate::client::handlers::temp_channel::reap_if_empty_temporary_on_server(
                self,
                &server_id,
                old_channel_id,
            )
            .await;
        }
        .instrument(client_span.clone())
        .instrument(server_span)
        .await;
        if let Err(error) = &result {
            client.in_tracing_scope(|| {
                if error.is_clean_disconnect() {
                    tracing::trace!("connection closed without TLS close_notify: {}", error);
                } else {
                    tracing::warn!("error handling connection: {}", error);
                }
            });
        }
        result
    }
}

#[cfg(test)]
mod client_snapshot_boundary_tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::client::state_log::ClientGlobalStateDelta;
    use crate::client_repository::ClientRepository;

    #[test]
    fn global_snapshot_start_clears_non_default_shadow_and_allows_reused_session_add() {
        let old_session = ClientSessionIdentifier::new(1, 7).unwrap();
        let unrelated_session = ClientSessionIdentifier::new(3, 8).unwrap();
        let viewer_session = ClientSessionIdentifier::new(2, 9).unwrap();
        let mut shadow = SessionChannelShadow::new();
        shadow.insert(old_session, 42);
        shadow.insert(unrelated_session, 84);

        assert_eq!(
            take_origin_sessions_from_shadow(&mut shadow, 1),
            vec![old_session]
        );
        assert!(!shadow.contains_key(&old_session));
        assert!(shadow.contains_key(&unrelated_session));

        let replacement = ClientStateOperation::AddClient {
            server_id: "tenant-alpha".to_owned(),
            session_id: old_session,
            client_instance_id: 200,
            real_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            tcp_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001),
            udp_addr: None,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738),
            cert_hash: None,
            login_time: chrono::Utc::now(),
            initial_state: ClientGlobalStateDelta::default(),
        };
        assert!(
            !should_skip_client_add_entry(&replacement, viewer_session, 300, &shadow),
            "the reused numeric session must be re-added after the global start boundary"
        );
    }

    #[tokio::test]
    async fn snapshot_end_boundary_sets_final_origin_vector() {
        let repo = ClientRepository::new(2, 16);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let peer = SocketAddr::new(ip, 30002);
        let local = SocketAddr::new(ip, 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let viewer = repo
            .allocate_web_client_in_server("tenant-alpha", ip, peer, local, tx)
            .await;
        viewer
            .update_last_client_versions(&HashMap::from([(1, 5)]))
            .await;

        apply_client_snapshot_end_vector(&viewer, &HashMap::from([(1, 17)])).await;
        assert_eq!(viewer.get_last_client_versions().await.get(&1), Some(&17));
    }

    #[tokio::test]
    async fn filtered_cross_server_broadcast_advances_global_origin_vector() {
        let repo = ClientRepository::new(2, 16);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let peer = SocketAddr::new(ip, 30002);
        let local = SocketAddr::new(ip, 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let viewer = repo
            .allocate_web_client_in_server("tenant-alpha", ip, peer, local, tx)
            .await;
        viewer
            .update_last_client_versions(&HashMap::from([(1, 5)]))
            .await;

        let remote_session = ClientSessionIdentifier::new(1, 7).unwrap();
        let entry = Arc::new(ClientStateLogEntry {
            version: 17,
            node_id: 1,
            timestamp: chrono::Utc::now().timestamp_millis(),
            channel_version_dep: None,
            op: ClientStateOperation::AddClient {
                server_id: "tenant-beta".to_owned(),
                session_id: remote_session,
                client_instance_id: 700,
                real_ip: ip,
                tcp_addr: SocketAddr::new(ip, 30001),
                udp_addr: None,
                local_addr: local,
                cert_hash: None,
                login_time: chrono::Utc::now(),
                initial_state: ClientGlobalStateDelta::default(),
            },
        });
        let broadcast = ClientStateBroadcastPayload::new(entry, HashMap::from([(1, 17)]));

        assert!(
            advance_client_log_vector_if_out_of_scope(&viewer, "tenant-alpha", &broadcast).await
        );
        assert_eq!(viewer.get_last_client_versions().await.get(&1), Some(&17));
        assert!(
            repo.get_client_in_server("tenant-beta", remote_session)
                .await
                .is_none(),
            "the connection consumer must advance only its vector, not apply the operation"
        );
    }
}

#[cfg(test)]
mod rate_tier_tests {
    use super::*;
    use shitspeak_messages::messages::Message;
    use shitspeak_proto::mumble_proto::{
        Authenticate, ContextAction, PermissionQuery, Ping, QueryUsers, RequestBlob, TextMessage,
        UserState, UserStats, VoiceTarget,
    };

    #[test]
    fn message_rate_tier_bypasses_queries_and_request_blobs() {
        assert_eq!(
            message_rate_tier(&Message::PermissionQuery(PermissionQuery::default())),
            None
        );
        assert_eq!(
            message_rate_tier(&Message::QueryUsers(QueryUsers::default())),
            None
        );
        assert_eq!(
            message_rate_tier(&Message::ContextAction(ContextAction::default())),
            None
        );
        assert_eq!(
            message_rate_tier(&Message::VoiceTarget(VoiceTarget::default())),
            None
        );
        assert_eq!(
            message_rate_tier(&Message::UserStats(UserStats::default())),
            None
        );
        assert_eq!(
            message_rate_tier(&Message::RequestBlob(RequestBlob::default())),
            None
        );
    }

    #[test]
    fn message_rate_tier_caps_amplification_prone_types() {
        assert_eq!(
            message_rate_tier(&Message::TextMessage(TextMessage::default())),
            Some(crate::rate_limits::MESSAGE_TIER_TEXT)
        );
    }

    #[test]
    fn message_rate_tier_defaults_to_state() {
        assert_eq!(
            message_rate_tier(&Message::UserState(UserState::default())),
            Some(crate::rate_limits::MESSAGE_TIER_STATE)
        );
        assert_eq!(
            message_rate_tier(&Message::Authenticate(Authenticate::default())),
            Some(crate::rate_limits::MESSAGE_TIER_STATE)
        );
        // Realtime messages never reach the limiter but must still classify.
        assert_eq!(
            message_rate_tier(&Message::Ping(Ping::default())),
            Some(crate::rate_limits::MESSAGE_TIER_STATE)
        );
    }
}
