use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tracing::Instrument;

use crate::channel_handler::{
    ChannelReplayError, ChannelTreeShadow, SessionChannelShadow, replay_channel_log_gap,
};
use crate::client::{
    AsyncMessageHandlerExt, Client, ClientInstanceId, ClientOutboundMessage,
    client_session_identifier::ClientSessionIdentifier,
    state_log::{
        ClientGlobalStateDelta, ClientStateBroadcastPayload, ClientStateLogEntry,
        ClientStateOperation,
    },
    visibility::UserVisibilityState,
};
use crate::errors::{
    HandleIncomingConnectionError, MessageHandlerError, ReadProtoMessageError,
    WriteProtoMessageError,
};
use crate::messages::encoder::Version;
use crate::messages::{Message, WriteMessageExt};
use crate::proxy_protocol::consume_proxy_protocol_connection_info;
use crate::types::default_server_id;
use crate::utils::{recv_mpsc_optional, recv_optional};
use shitspeak_state::{ChannelOp, ChannelOperation};

use super::Server;
use super::client_projection::ClientProjectionState;
use super::client_projection_pool::ClientProjectionRegistration;
use super::entrypoints::normalize_sni_name;
use super::extensions::{ALPN_MUMBLE, AlpnConnectionInfo};

type ClientLogReceiver = tokio::sync::broadcast::Receiver<Arc<ClientStateBroadcastPayload>>;
type ChannelLogReceiver = tokio::sync::broadcast::Receiver<Arc<ChannelOperation>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelLogReceiveOutcome {
    Continue,
    Closed,
}

const CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT: usize = 64;
const CLIENT_LOG_BROADCAST_DRAIN_LIMIT: usize = 4;
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

fn map_channel_replay_error(error: ChannelReplayError) -> HandleIncomingConnectionError {
    match error {
        ChannelReplayError::ClientWriteFailed(error) => {
            HandleIncomingConnectionError::ClientWriteFailed(error)
        }
    }
}

pub(super) async fn activate_client_subscriptions(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    client_log_rx: &mut Option<ClientLogReceiver>,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
    channel_tree_shadow: &mut ChannelTreeShadow,
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
    if let Some(baseline) = post_auth_baseline {
        let (staged_session_shadow, staged_channel_tree_shadow, staged_user_visibility) =
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
        let channels = server.channels.get_all_in_server(&server_id).await;
        if server.get_hide_channels_without_traverse() {
            for channel in channels {
                if crate::channel_handler::can_view_channel_with_ancestors(
                    server, client, channel.id,
                )
                .await
                {
                    channel_tree_shadow.insert(channel.id);
                }
            }
        } else {
            channel_tree_shadow.extend(channels.into_iter().map(|channel| channel.id));
        }
        if server.get_hide_users_without_traverse() {
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
                    .filter(|client| client.is_authenticated() && client.is_published())
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
        session_channel_shadow,
        user_visibility,
        &server_id,
        client_session_id,
        client.get_last_client_versions().await,
    )
    .await?;
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
    let staged_client_versions = client.get_last_client_versions().await;
    // Native clients no longer retain their own log receivers after auth. The
    // shard's registration hook catches up from these exact snapshot cursors.
    drop(staged_channel_subscription);
    drop(client.take_client_state_subscription());

    let (baseline, last_client_versions, channel_snapshot_version) =
        if let Some(baseline) = client.take_post_auth_baseline() {
            (baseline, staged_client_versions, staged_channel_version)
        } else {
            tracing::warn!(
                server_id,
                session = u32::from(client_session_id),
                "post-auth baseline missing; atomically recapturing projection snapshots"
            );
            let (snapshot_clients, snapshot_versions, snapshot_client_rx) = server
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
            if server.get_hide_channels_without_traverse() {
                for channel in &channels {
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
            if server.get_hide_users_without_traverse() {
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
                        .filter(|client| client.is_authenticated() && client.is_published())
                        .map(|client| (client.get_session_id(), client.get_current_channel_id())),
                );
            }
            (
                crate::client::PostAuthBaseline::with_user_visibility(
                    session_channel_shadow,
                    channel_tree_shadow,
                    user_visibility,
                ),
                snapshot_versions,
                snapshot_channel_version,
            )
        };

    let state = ClientProjectionState::from_post_auth_baseline(
        Arc::downgrade(server),
        Arc::clone(client),
        baseline,
        last_client_versions,
        channel_snapshot_version,
    );

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
    Ok(())
}

async fn replay_client_log_entries_since(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    server_id: &str,
    client_session_id: ClientSessionIdentifier,
    last_seen: HashMap<u16, u64>,
) -> Result<(), HandleIncomingConnectionError> {
    let (missed, new_versions) = server
        .clients
        .replay_entries_since_in_server_for_client(
            server_id,
            &last_seen,
            client.get_session_id(),
            client.client_instance_id(),
        )
        .await
        .map_err(|()| HandleIncomingConnectionError::ClientLogGapUnrecoverable)?;

    let mut out = Vec::new();
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
    client.update_last_client_versions(&new_versions).await;
    Ok(())
}

async fn finish_handler_result(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    projection_registration: &mut Option<ClientProjectionRegistration>,
    result: Result<(), MessageHandlerError>,
) -> Result<(), HandleIncomingConnectionError> {
    if matches!(result, Err(MessageHandlerError::AuthRejection(_))) {
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
    let handler_server = Arc::clone(server);
    let handler_client = Arc::clone(client);
    handler_tasks.spawn(async move {
        handler_client
            .handle_message(&handler_server, message)
            .await
    });
}

fn is_own_client_log_entry(
    op: &ClientStateOperation,
    session_id: ClientSessionIdentifier,
    client_instance_id: ClientInstanceId,
) -> bool {
    op.session_id() == Some(session_id) && op.client_instance_id() == client_instance_id
}

pub(super) fn sorted_channel_ids(channel_ids: &HashSet<u32>) -> Vec<u32> {
    let mut channel_ids: Vec<_> = channel_ids.iter().copied().collect();
    channel_ids.sort_unstable();
    channel_ids
}

async fn project_message_with_visibility_shadows(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
) -> Vec<Message> {
    crate::channel_handler::project_message_with_visibility_shadows(
        server,
        client,
        channel_tree_shadow,
        user_visibility,
        session_channel_shadow,
        server_id,
        message,
    )
    .await
}

async fn append_client_log_entry_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
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
            replay_channel_log_gap(
                server,
                client,
                &server.channels,
                channel_tree_shadow,
                session_channel_shadow,
                user_visibility,
                client_session_id,
                last_ch,
                dep + 1,
            )
            .await
            .map_err(map_channel_replay_error)?;
        }
    }

    out.extend(
        crate::channel_handler::project_client_log_entry_transition(
            server,
            client,
            channel_tree_shadow,
            user_visibility,
            session_channel_shadow,
            entry,
        )
        .await,
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
    let mut rx = match client.take_outbound_message_rx() {
        Some(rx) => rx,
        None => {
            span.in_scope(|| {
                tracing::warn!(
                    session = u32::from(client.get_session_id()),
                    "native client writer task already spawned"
                );
            });
            return None;
        }
    };
    let mut voice_rx = match client.take_voice_tcp_rx() {
        Some(rx) => rx,
        None => {
            span.in_scope(|| {
                tracing::warn!(
                    session = u32::from(client.get_session_id()),
                    "native client voice TCP queue already claimed"
                );
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
        .instrument(span),
    ))
}

async fn process_channel_log_result(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    result: Option<Result<Arc<ChannelOperation>, tokio::sync::broadcast::error::RecvError>>,
) -> Result<ChannelLogReceiveOutcome, HandleIncomingConnectionError> {
    match result {
        Some(Ok(op)) => {
            if op.server_id != client.server_id() {
                return Ok(ChannelLogReceiveOutcome::Continue);
            }
            let last = client.get_last_channel_version().await;
            if op.version <= last && !op.is_root_name_config_update() {
                return Ok(ChannelLogReceiveOutcome::Continue);
            }
            if op.version > last {
                replay_channel_log_gap(
                    server,
                    client,
                    &server.channels,
                    channel_tree_shadow,
                    session_channel_shadow,
                    user_visibility,
                    client_session_id,
                    last,
                    op.version,
                )
                .await
                .map_err(map_channel_replay_error)?;
            }
            let last_after_replay = client.get_last_channel_version().await;
            if op.version <= last_after_replay && !op.is_root_name_config_update() {
                return Ok(ChannelLogReceiveOutcome::Continue);
            }

            let refresh_scope =
                crate::client::visibility::visibility_refresh_scope_for_channel_operation_with_state(
                    server,
                    &op,
                    user_visibility,
                )
                .await;
            let channel_refresh = crate::channel_handler::prepare_channel_visibility_refresh(
                server,
                client,
                channel_tree_shadow,
                &refresh_scope,
            )
            .await;
            let messages =
                crate::channel_handler::convert_channel_operation_to_messages_with_shadow(
                    server,
                    client,
                    &op,
                    &server.channels,
                    Some(session_channel_shadow),
                )
                .await;
            let mut outbound = Vec::new();
            let mut deferred_channel_removals = Vec::new();
            for msg in messages {
                if matches!(msg, Message::ChannelRemove(_)) {
                    deferred_channel_removals.extend(
                        crate::channel_handler::project_channel_message(
                            server,
                            client,
                            channel_tree_shadow,
                            &msg,
                        )
                        .await,
                    );
                    continue;
                }
                for projected in project_message_with_visibility_shadows(
                    server,
                    client,
                    channel_tree_shadow,
                    user_visibility,
                    session_channel_shadow,
                    &client.server_id(),
                    &msg,
                )
                .await
                {
                    if matches!(&projected, Message::ChannelRemove(_)) {
                        deferred_channel_removals.push(projected);
                    } else {
                        outbound.push(projected);
                    }
                }
            }

            channel_refresh.apply_additions(channel_tree_shadow);
            channel_refresh.append_additions_to(&mut outbound);
            let projected = crate::client::visibility::visibility_refresh_messages_with_shadow(
                server,
                client,
                user_visibility,
                session_channel_shadow,
                &client.server_id(),
                refresh_scope,
            )
            .await;
            for msg in projected {
                channel_tree_shadow.sync_message(&msg);
                outbound.push(msg);
            }
            channel_refresh.apply_removals(channel_tree_shadow);
            channel_refresh.append_removals_to(&mut outbound);
            for message in deferred_channel_removals {
                if let Message::ChannelRemove(channel_remove) = &message {
                    if !channel_tree_shadow.contains(&channel_remove.channel_id) {
                        continue;
                    }
                }
                channel_tree_shadow.sync_message(&message);
                outbound.push(message);
            }
            crate::channel_handler::remove_deleted_channels_from_shadow(
                server.get_channels(),
                &op,
                channel_tree_shadow,
            );
            client
                .write_proto_message_batch(&outbound)
                .await
                .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
            if op.version > last_after_replay {
                client.set_last_channel_version(op.version).await;
            }
            Ok(ChannelLogReceiveOutcome::Continue)
        }
        Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
            let last = client.get_last_channel_version().await;
            replay_channel_log_gap(
                server,
                client,
                &server.channels,
                channel_tree_shadow,
                session_channel_shadow,
                user_visibility,
                client_session_id,
                last,
                u64::MAX,
            )
            .await
            .map_err(map_channel_replay_error)?;
            Ok(ChannelLogReceiveOutcome::Continue)
        }
        Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
            Ok(ChannelLogReceiveOutcome::Closed)
        }
        None => Ok(ChannelLogReceiveOutcome::Continue),
    }
}

async fn drain_ready_channel_log_before_client_log(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
) -> Result<ChannelLogReceiveOutcome, HandleIncomingConnectionError> {
    let Some(rx) = channel_log_rx.as_mut() else {
        return Ok(ChannelLogReceiveOutcome::Continue);
    };

    for _ in 0..CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT {
        let result = match rx.try_recv() {
            Ok(op) => Some(Ok(op)),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                Some(Err(tokio::sync::broadcast::error::RecvError::Closed))
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => Some(Err(
                tokio::sync::broadcast::error::RecvError::Lagged(skipped),
            )),
        };

        if process_channel_log_result(
            server,
            client,
            client_session_id,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            result,
        )
        .await?
            == ChannelLogReceiveOutcome::Closed
        {
            return Ok(ChannelLogReceiveOutcome::Closed);
        }
    }

    Ok(ChannelLogReceiveOutcome::Continue)
}

async fn process_client_log_broadcasts(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    first: Arc<ClientStateBroadcastPayload>,
    rx: &mut ClientLogReceiver,
) -> Result<(), HandleIncomingConnectionError> {
    let mut broadcasts = Vec::with_capacity(CLIENT_LOG_BROADCAST_DRAIN_LIMIT);
    broadcasts.push(first);
    for _ in 1..CLIENT_LOG_BROADCAST_DRAIN_LIMIT {
        match rx.try_recv() {
            Ok(broadcast) => broadcasts.push(broadcast),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                replay_client_log_subscription_gap(
                    server,
                    client,
                    client_session_id,
                    channel_tree_shadow,
                    session_channel_shadow,
                    user_visibility,
                )
                .await?;
                return Ok(());
            }
        }
    }

    let client_server_id = client.server_id();
    let mut out = Vec::new();
    for broadcast in broadcasts {
        append_client_log_broadcast_messages(
            server,
            client,
            client_session_id,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            &client_server_id,
            broadcast,
            &mut out,
        )
        .await?;
    }

    client
        .write_proto_message_batch(&out)
        .await
        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
    Ok(())
}

async fn append_client_log_broadcast_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    client_server_id: &str,
    broadcast: Arc<ClientStateBroadcastPayload>,
    out: &mut Vec<Message>,
) -> Result<(), HandleIncomingConnectionError> {
    tracing::trace!("Received client log broadcast: {:?}", broadcast);

    let entry = &broadcast.entry;
    if matches!(entry.op, ClientStateOperation::ResetNode { .. }) {
        match broadcast.versions.get(&entry.node_id).copied() {
            Some(0) => {
                // Snapshot/reset start is global to an origin, whereas a
                // connection shadow is scoped to one virtual server. Handle
                // it before the server-id filter and explicitly evict every
                // shadowed session from that origin. This also makes a reused
                // numeric session accept the replacement AddClient.
                let sessions =
                    take_origin_sessions_from_shadow(session_channel_shadow, entry.node_id);
                for session in sessions {
                    let removal: Message = crate::messages::encoder::UserRemove {
                        session: u32::from(session),
                        actor: None,
                        reason: None,
                        ban: Some(false),
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
                client.remove_last_client_version(entry.node_id).await;
                return Ok(());
            }
            Some(_) => {
                // Snapshot/reset end: materialized AddClient entries have
                // already rebuilt the shadow. Only publish the final owner
                // vector; replaying ResetNode visibility here would disturb
                // that freshly reconstructed state.
                apply_client_snapshot_end_vector(client, &broadcast.versions).await;
                return Ok(());
            }
            None => {}
        }
    }
    if advance_client_log_vector_if_out_of_scope(client, client_server_id, &broadcast).await {
        return Ok(());
    }
    let mut last_seen = client.get_last_client_versions().await;
    let mut last_for_node = last_seen.get(&entry.node_id).copied().unwrap_or(0);
    match broadcast.versions.get(&entry.node_id).copied() {
        Some(0) => {
            client.remove_last_client_version(entry.node_id).await;
            last_seen.remove(&entry.node_id);
            last_for_node = entry.version.saturating_sub(1);
        }
        Some(current) if current < last_for_node => {
            client.remove_last_client_version(entry.node_id).await;
            last_seen.remove(&entry.node_id);
            last_for_node = 0;
        }
        _ => {}
    }
    if entry.version <= last_for_node {
        return Ok(());
    }
    if entry.version > last_for_node + 1 {
        client
            .write_proto_message_batch(out)
            .await
            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
        out.clear();
        replay_client_log_entries_since(
            server,
            client,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            client_server_id,
            client_session_id,
            last_seen,
        )
        .await?;
        return Ok(());
    }

    if should_skip_client_add_entry(
        &entry.op,
        client.get_session_id(),
        client.client_instance_id(),
        session_channel_shadow,
    ) {
        client
            .update_last_client_versions(&broadcast.versions)
            .await;
        return Ok(());
    }

    append_client_log_entry_messages(
        server,
        client,
        client_session_id,
        channel_tree_shadow,
        user_visibility,
        session_channel_shadow,
        client_server_id,
        entry,
        out,
    )
    .await?;
    client
        .update_last_client_versions(&broadcast.versions)
        .await;
    Ok(())
}

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

async fn apply_client_snapshot_end_vector(client: &Arc<Box<Client>>, versions: &HashMap<u16, u64>) {
    client.update_last_client_versions(versions).await;
}

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

async fn replay_client_log_subscription_gap(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> Result<(), HandleIncomingConnectionError> {
    let last_seen = client.get_last_client_versions().await;
    let server_id = client.server_id();
    replay_client_log_entries_since(
        server,
        client,
        channel_tree_shadow,
        session_channel_shadow,
        user_visibility,
        &server_id,
        client_session_id,
        last_seen,
    )
    .await
}

impl Server {
    pub async fn handle_incoming_connection(
        self: &Arc<Box<Self>>,
        mut tcp_stream: tokio::net::TcpStream,
        remote_addr: std::net::SocketAddr,
        provisional_server_id: String,
    ) -> Result<(), HandleIncomingConnectionError> {
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
        let client_addr = proxy_connection
            .and_then(|info| info.client_address())
            .map(|addr| SocketAddr::new(addr.ip(), addr.port()))
            .unwrap_or(remote_addr);
        let real_ip = client_addr.ip();

        let local_addr = tcp_stream.local_addr()?;
        tracing::info!(
            %remote_addr,
            %client_addr,
            %local_addr,
            uses_proxy_protocol,
            "TLS handshake starting"
        );
        let tls_ja4 = crate::tls_fingerprint::peek_tls_ja4(&tcp_stream).await?;
        let tls_acceptor = self.tls_acceptor.read().clone();
        let tls_stream = tls_acceptor.accept(tcp_stream).await?;
        let server_id = self.resolve_tls_server_id(&provisional_server_id, local_addr, &tls_stream);
        tracing::info!(
            %remote_addr,
            %client_addr,
            %local_addr,
            server_id,
            alpn = ?tls_stream.get_ref().1.alpn_protocol().map(String::from_utf8_lossy),
            tls_ja4 = ?tls_ja4,
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
                    tls_ja4,
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
            tls_ja4,
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
        tls_ja4: Option<String>,
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
            .allocate_local_client_in_server(
                server_id,
                real_ip,
                remote_addr,
                None,
                local_addr,
                tls_stream,
                tls_ja4,
                uses_proxy_protocol,
            )
            .await;

        let client_span = client.tracing_span();

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

async fn replay_client_log_gap(
    client: &Arc<Box<crate::client::Client>>,
    repo: &crate::client_repository::ClientRepository,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    node_id: u16,
    last: u64,
    current: u64,
) -> Result<(), ()> {
    if current <= last + 1 {
        return Ok(());
    }

    tracing::warn!(
        "Client {:?} missed client log entries: node={} last={} current={}",
        session_id,
        node_id,
        last,
        current,
    );

    let missed = repo.get_log_since_for_node(node_id, last).await;
    if missed.is_empty() && last > 0 {
        tracing::error!(
            "Client {:?} client log gap unrecoverable (node={}, last={})",
            session_id,
            node_id,
            last,
        );
        return Err(());
    }

    for entry in &missed {
        if entry.version >= current {
            break;
        }
        if is_own_client_log_entry(&entry.op, session_id, client.client_instance_id()) {
            continue;
        }
        if let Some(msg) = entry.to_message(repo).await {
            if client.write_proto_message(&msg).await.is_err() {
                return Err(());
            }
        }
        let mut ver = HashMap::new();
        ver.insert(entry.node_id, entry.version);
        client.update_last_client_versions(&ver).await;
    }

    Ok(())
}

#[cfg(test)]
mod client_snapshot_boundary_tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
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
