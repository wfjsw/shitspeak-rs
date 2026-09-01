//! Per-client state used by the sharded state-log projection workers.
//!
//! This module deliberately contains no receiver or task ownership. A shard owns
//! one `ClientProjectionState`, feeds channel operations before client-log
//! operations, and delivers the returned owned batch without awaiting the
//! connection writer.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Instant;

use async_trait::async_trait;
use shitspeak_state::ChannelOperation;

use crate::channel_handler::{ChannelPermissionShadow, ChannelTreeShadow, SessionChannelShadow};
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::client::state_log::{
    ClientStateBroadcastPayload, ClientStateLogEntry, ClientStateOperation,
};
use crate::client::visibility::UserVisibilityState;
use crate::client::{Client, ClientInstanceId, OwnedMessageBatch, PostAuthBaseline};
use crate::errors::HandleIncomingConnectionError;
use crate::observability::{
    ClientProjectionDisconnectReason, ClientProjectionRecoveryOutcome,
    ClientProjectionRecoveryReason, record_client_projection_disconnect,
    record_client_projection_recovery,
};
use shitspeak_messages::messages::Message;

use super::Server;
use super::sharded_subscriber::{DeliverResult, LagAction, ShardedSubscriber};

/// The ordered event stream consumed by the projection shards. Existing
/// channel/client publishers remain unchanged; the bridge that owns their
/// receivers wraps each item in this enum.
#[derive(Clone, Debug)]
pub(crate) enum ClientProjectionEvent {
    Channel(Arc<ChannelOperation>),
    Client(Arc<ClientStateBroadcastPayload>),
    VisibilityReload,
    ClientLagged(u64),
    ChannelLagged(u64),
}

/// Projection state with a single owner: the shard to which the client is
/// registered.
///
/// Shadows and cursors stay here instead of on the connection task. Keeping
/// the fields private makes it impossible for a connection to mutate half of
/// a projection baseline after registration.
pub(crate) struct ClientProjectionState {
    server: Weak<Box<Server>>,
    client: Arc<Box<Client>>,
    channel_tree_shadow: ChannelTreeShadow,
    channel_permission_shadow: ChannelPermissionShadow,
    session_channel_shadow: SessionChannelShadow,
    user_visibility: UserVisibilityState,
    last_client_versions: HashMap<u16, u64>,
    last_client_epochs: HashMap<u16, u64>,
    last_channel_version: u64,
    replay_client_log: bool,
    replay_channel_log: bool,
    reconcile_root_channel: bool,
    client_recovery_reason: Option<ClientProjectionRecoveryReason>,
    baseline_visibility_generation: Option<u64>,
}

impl ClientProjectionState {
    /// Build a shard-owned state from the post-authentication snapshot and the
    /// exact cursors associated with that snapshot.
    pub(crate) fn from_post_auth_baseline(
        server: Weak<Box<Server>>,
        client: Arc<Box<Client>>,
        baseline: PostAuthBaseline,
        last_client_versions: HashMap<u16, u64>,
        last_client_epochs: HashMap<u16, u64>,
        last_channel_version: u64,
    ) -> Self {
        let (session_channel_shadow, channel_tree_shadow, user_visibility, visibility_generation) =
            baseline.into_parts();
        let mut state = Self::new(
            server,
            client,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            last_client_versions,
            last_client_epochs,
            last_channel_version,
        );
        state.baseline_visibility_generation = visibility_generation;
        state
    }

    pub(crate) fn new(
        server: Weak<Box<Server>>,
        client: Arc<Box<Client>>,
        channel_tree_shadow: ChannelTreeShadow,
        session_channel_shadow: SessionChannelShadow,
        user_visibility: UserVisibilityState,
        last_client_versions: HashMap<u16, u64>,
        last_client_epochs: HashMap<u16, u64>,
        last_channel_version: u64,
    ) -> Self {
        Self {
            server,
            client,
            channel_tree_shadow,
            channel_permission_shadow: ChannelPermissionShadow::new(),
            session_channel_shadow,
            user_visibility,
            last_client_versions,
            last_client_epochs,
            last_channel_version,
            replay_client_log: false,
            replay_channel_log: false,
            reconcile_root_channel: false,
            client_recovery_reason: None,
            baseline_visibility_generation: None,
        }
    }

    pub(crate) fn client_instance_id(&self) -> ClientInstanceId {
        self.client.client_instance_id()
    }

    fn server(&self) -> Result<Arc<Box<Server>>, HandleIncomingConnectionError> {
        self.server.upgrade().ok_or_else(|| {
            HandleIncomingConnectionError::IOError(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "server stopped while client projection was registered",
            ))
        })
    }

    async fn resynchronize(
        &mut self,
        outbound: &mut Vec<Message>,
    ) -> Result<(), HandleIncomingConnectionError> {
        let server = self.server()?;
        if self.replay_channel_log {
            self.replay_channel_log = false;
            let last = self.last_channel_version;
            self.append_channel_gap(&server, last, u64::MAX, outbound)
                .await?;
            if self.reconcile_root_channel {
                self.reconcile_root_channel = false;
                self.append_current_root_channel(&server, outbound).await;
            }
        }
        if self.replay_client_log {
            self.replay_client_log = false;
            let reason = self.client_recovery_reason.take();
            self.append_client_gap(&server, outbound, reason).await?;
        }
        Ok(())
    }

    async fn append_current_root_channel(
        &mut self,
        server: &Arc<Box<Server>>,
        outbound: &mut Vec<Message>,
    ) {
        let server_id = self.client.server_id();
        let Some(root) = server.channels.get_channel_in_server(&server_id, 0).await else {
            return;
        };
        let message: Message =
            crate::channel_handler::build_channel_state_message(server, &self.client, &root)
                .await
                .into();
        self.channel_tree_shadow.sync_message(&message);
        self.channel_permission_shadow.sync_message(&message);
        outbound.push(message);
    }

    async fn append_channel_operation(
        &mut self,
        server: &Arc<Box<Server>>,
        operation: &ChannelOperation,
        outbound: &mut Vec<Message>,
    ) -> Result<(), HandleIncomingConnectionError> {
        if operation.server_id != self.client.server_id() {
            return Ok(());
        }

        if let shitspeak_state::ChannelOp::UpdateChannel { id: 0, patch } = &operation.op
            && let Some(name) = patch.name.as_deref()
            && server
                .channels
                .get_channel_in_server(&operation.server_id, 0)
                .await
                .is_some_and(|root| root.name != name)
        {
            return Ok(());
        }

        let last = self.last_channel_version;
        if operation.version <= last && !operation.is_root_name_config_update() {
            return Ok(());
        }
        if operation.version > last {
            self.append_channel_gap(server, last, operation.version, outbound)
                .await?;
        }
        if operation.version <= self.last_channel_version && !operation.is_root_name_config_update()
        {
            return Ok(());
        }

        self.append_projected_channel_operation(server, operation, outbound)
            .await;
        if operation.version > self.last_channel_version {
            self.last_channel_version = operation.version;
        }
        Ok(())
    }

    async fn append_projected_channel_operation(
        &mut self,
        server: &Arc<Box<Server>>,
        operation: &ChannelOperation,
        outbound: &mut Vec<Message>,
    ) {
        if matches!(
            &operation.op,
            shitspeak_state::ChannelOp::InstallSnapshot { .. }
        ) {
            self.channel_permission_shadow.clear();
        }
        let acl_context = crate::channel_handler::ClientAclOperationContext::for_operation(
            server,
            &self.client,
            &server.channels,
            operation,
        )
        .await;
        let refresh_scope =
            crate::client::visibility::visibility_refresh_scope_for_channel_operation_with_state_for_client(
                server,
                &self.client,
                operation,
                &mut self.user_visibility,
            )
            .await;
        let channel_refresh =
            crate::channel_handler::prepare_channel_visibility_refresh_with_acl_context(
                server,
                &self.client,
                &self.channel_tree_shadow,
                &refresh_scope,
                acl_context.as_ref(),
            )
            .await;
        let messages =
            crate::channel_handler::convert_channel_operation_to_messages_with_acl_context(
                server,
                &self.client,
                operation,
                &server.channels,
                Some(&mut self.session_channel_shadow),
                Some(&self.channel_permission_shadow),
                acl_context.as_ref(),
            )
            .await;
        let mut deferred_channel_removals = Vec::new();
        let server_id = self.client.server_id();
        for message in messages {
            if matches!(message, Message::ChannelRemove(_)) {
                deferred_channel_removals.extend(
                    crate::channel_handler::project_channel_message(
                        server,
                        &self.client,
                        &mut self.channel_tree_shadow,
                        &message,
                    )
                    .await,
                );
                continue;
            }
            for projected in crate::channel_handler::project_message_with_visibility_shadows(
                server,
                &self.client,
                &mut self.channel_tree_shadow,
                &mut self.user_visibility,
                &mut self.session_channel_shadow,
                &server_id,
                &message,
            )
            .await
            {
                if matches!(&projected, Message::ChannelRemove(_)) {
                    deferred_channel_removals.push(projected);
                } else {
                    self.channel_permission_shadow.sync_message(&projected);
                    outbound.push(projected);
                }
            }
        }

        channel_refresh.apply_additions(&mut self.channel_tree_shadow);
        channel_refresh.append_additions_to(outbound);
        let projected =
            crate::client::visibility::visibility_refresh_messages_with_shadow_and_acl_context(
                server,
                &self.client,
                &mut self.user_visibility,
                &mut self.session_channel_shadow,
                &server_id,
                refresh_scope,
                acl_context.as_ref(),
            )
            .await;
        for message in projected {
            self.channel_tree_shadow.sync_message(&message);
            self.channel_permission_shadow.sync_message(&message);
            outbound.push(message);
        }
        channel_refresh.apply_removals(&mut self.channel_tree_shadow);
        channel_refresh.apply_permission_removals(&mut self.channel_permission_shadow);
        channel_refresh.append_removals_to(outbound);
        for message in deferred_channel_removals {
            if let Message::ChannelRemove(channel_remove) = &message
                && !self
                    .channel_tree_shadow
                    .contains(&channel_remove.channel_id)
            {
                continue;
            }
            self.channel_tree_shadow.sync_message(&message);
            self.channel_permission_shadow.sync_message(&message);
            outbound.push(message);
        }
        crate::channel_handler::remove_deleted_channels_from_shadow(
            server.get_channels(),
            operation,
            &mut self.channel_tree_shadow,
        );
        crate::channel_handler::remove_deleted_channel_permissions_from_shadow(
            server.get_channels(),
            operation,
            &mut self.channel_permission_shadow,
        );
    }

    async fn append_channel_gap(
        &mut self,
        server: &Arc<Box<Server>>,
        last: u64,
        current: u64,
        outbound: &mut Vec<Message>,
    ) -> Result<(), HandleIncomingConnectionError> {
        if current <= last.saturating_add(1) {
            return Ok(());
        }

        let server_id = self.client.server_id();
        let missed = server
            .channels
            .get_log_since_in_server(&server_id, last)
            .await;
        if missed.is_empty()
            || missed
                .first()
                .is_some_and(|entry| entry.version > last.saturating_add(1))
        {
            let latest = server.channels.current_version_in_server(&server_id);
            if latest > last {
                self.append_channel_snapshot(server, &server_id, outbound)
                    .await;
            }
            return Ok(());
        }

        for entry in &missed {
            if entry.version >= current {
                break;
            }
            self.append_projected_channel_operation(server, entry, outbound)
                .await;
            self.last_channel_version = entry.version;
        }
        Ok(())
    }

    async fn append_channel_snapshot(
        &mut self,
        server: &Arc<Box<Server>>,
        server_id: &str,
        outbound: &mut Vec<Message>,
    ) {
        let (snapshot, latest) = server
            .channels
            .ordered_snapshot_with_version_in_server(server_id)
            .await;
        self.channel_permission_shadow.clear();
        let previous = self.channel_tree_shadow.clone();
        let mut current = ChannelTreeShadow::new();
        let messages = crate::channel_handler::build_visible_ordered_channel_snapshot_messages(
            server,
            &self.client,
            &snapshot,
            &mut current,
            server.get_send_permission_info(),
        )
        .await;
        let removed_channel_ids = previous
            .difference(&current)
            .copied()
            .collect::<std::collections::HashSet<_>>();
        let removed = crate::channel_handler::channel_removal_ids_descendant_first(
            &snapshot,
            &removed_channel_ids,
        );

        self.channel_tree_shadow = current;
        outbound.extend(messages);
        let mut visibility_scope = crate::client::visibility::VisibilityRefreshScope::new();
        visibility_scope.include_all_channels();
        visibility_scope.include_known_users();
        let visibility_messages =
            crate::client::visibility::visibility_refresh_messages_with_shadow(
                server,
                &self.client,
                &mut self.user_visibility,
                &mut self.session_channel_shadow,
                server_id,
                visibility_scope,
            )
            .await;
        self.channel_permission_shadow
            .sync_messages(visibility_messages.iter());
        outbound.extend(visibility_messages);
        for channel_id in removed {
            let message =
                shitspeak_messages::messages::encoder::ChannelRemove { channel_id }.into();
            self.channel_permission_shadow.sync_message(&message);
            outbound.push(message);
        }
        self.last_channel_version = latest;
    }

    async fn append_client_broadcast(
        &mut self,
        server: &Arc<Box<Server>>,
        broadcast: &ClientStateBroadcastPayload,
        outbound: &mut Vec<Message>,
    ) -> Result<(), HandleIncomingConnectionError> {
        tracing::trace!(?broadcast, "shard received client log broadcast");
        let entry = &broadcast.entry;
        if matches!(entry.op, ClientStateOperation::ResetNode { .. }) {
            if entry.op.server_id() != self.client.server_id() {
                if let Some(version) = broadcast.versions.get(&entry.node_id).copied()
                    && version != 0
                {
                    merge_version_vector(&mut self.last_client_versions, &broadcast.versions);
                }
                return Ok(());
            }
            match broadcast.versions.get(&entry.node_id).copied() {
                Some(0) => {
                    self.append_origin_reset(server, entry.node_id, outbound)
                        .await;
                    self.last_client_versions.remove(&entry.node_id);
                    self.last_client_epochs.remove(&entry.node_id);
                    return Ok(());
                }
                Some(_) => {
                    merge_version_vector(&mut self.last_client_versions, &broadcast.versions);
                    return Ok(());
                }
                None => {}
            }
        }

        let client_server_id = self.client.server_id();
        if entry.op.server_id() != client_server_id {
            if let Some(&version) = broadcast.versions.get(&entry.node_id) {
                merge_one_version(&mut self.last_client_versions, entry.node_id, version);
            }
            return Ok(());
        }

        let mut last_for_node = self
            .last_client_versions
            .get(&entry.node_id)
            .copied()
            .unwrap_or(0);
        match broadcast.versions.get(&entry.node_id).copied() {
            Some(0) => {
                self.last_client_versions.remove(&entry.node_id);
                self.last_client_epochs.remove(&entry.node_id);
                last_for_node = entry.version.saturating_sub(1);
            }
            Some(current) if current < last_for_node => {
                self.last_client_versions.remove(&entry.node_id);
                last_for_node = 0;
            }
            _ => {}
        }
        if entry.version <= last_for_node {
            return Ok(());
        }
        if entry.version > last_for_node.saturating_add(1) {
            self.append_client_gap(server, outbound, None).await?;
            return Ok(());
        }
        if should_skip_client_add_entry(
            &entry.op,
            self.client.get_session_id(),
            self.client.client_instance_id(),
            &self.session_channel_shadow,
        ) {
            merge_version_vector(&mut self.last_client_versions, &broadcast.versions);
            return Ok(());
        }

        let canonical_message = broadcast.canonical_message(&server.clients).await;
        self.append_client_entry_with_canonical(server, entry, canonical_message, outbound)
            .await?;
        merge_version_vector(&mut self.last_client_versions, &broadcast.versions);
        Ok(())
    }

    async fn append_origin_reset(
        &mut self,
        server: &Arc<Box<Server>>,
        origin: u16,
        outbound: &mut Vec<Message>,
    ) {
        let viewer_session = self.client.get_session_id();
        let viewer_old_channel = self.session_channel_shadow.get(&viewer_session).copied();
        let sessions = take_origin_sessions_from_shadow(&mut self.session_channel_shadow, origin);
        let server_id = self.client.server_id();
        for session in sessions {
            if session == viewer_session {
                self.session_channel_shadow.insert(
                    session,
                    viewer_old_channel.unwrap_or_else(|| self.client.get_current_channel_id()),
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
            outbound.extend(
                crate::client::visibility::project_message_with_shadow(
                    server,
                    &self.client,
                    &mut self.user_visibility,
                    &mut self.session_channel_shadow,
                    &server_id,
                    &removal,
                )
                .await,
            );
        }
    }

    async fn append_client_entry(
        &mut self,
        server: &Arc<Box<Server>>,
        entry: &ClientStateLogEntry,
        outbound: &mut Vec<Message>,
    ) -> Result<(), HandleIncomingConnectionError> {
        if let Some(dependency) = entry.channel_version_dep
            && self.last_channel_version < dependency
        {
            let last = self.last_channel_version;
            self.append_channel_gap(server, last, dependency.saturating_add(1), outbound)
                .await?;
            if self.last_channel_version < dependency {
                return Err(HandleIncomingConnectionError::ChannelLogGapUnrecoverable);
            }
        }
        let messages = crate::channel_handler::project_client_log_entry_transition(
            server,
            &self.client,
            &mut self.channel_tree_shadow,
            &mut self.user_visibility,
            &mut self.session_channel_shadow,
            entry,
        )
        .await;
        outbound.extend(
            crate::channel_handler::suppress_known_projected_permission_messages(
                messages,
                &mut self.channel_permission_shadow,
            ),
        );
        Ok(())
    }

    async fn append_client_entry_with_canonical(
        &mut self,
        server: &Arc<Box<Server>>,
        entry: &ClientStateLogEntry,
        canonical_message: Option<&Message>,
        outbound: &mut Vec<Message>,
    ) -> Result<(), HandleIncomingConnectionError> {
        if let Some(dependency) = entry.channel_version_dep
            && self.last_channel_version < dependency
        {
            let last = self.last_channel_version;
            self.append_channel_gap(server, last, dependency.saturating_add(1), outbound)
                .await?;
            if self.last_channel_version < dependency {
                return Err(HandleIncomingConnectionError::ChannelLogGapUnrecoverable);
            }
        }
        let messages = crate::channel_handler::project_client_log_entry_transition_with_canonical(
            server,
            &self.client,
            &mut self.channel_tree_shadow,
            &mut self.user_visibility,
            &mut self.session_channel_shadow,
            entry,
            canonical_message,
        )
        .await;
        outbound.extend(
            crate::channel_handler::suppress_known_projected_permission_messages(
                messages,
                &mut self.channel_permission_shadow,
            ),
        );
        Ok(())
    }

    async fn append_client_gap(
        &mut self,
        server: &Arc<Box<Server>>,
        outbound: &mut Vec<Message>,
        trigger_reason: Option<ClientProjectionRecoveryReason>,
    ) -> Result<(), HandleIncomingConnectionError> {
        let started_at = Instant::now();
        let server_id = self.client.server_id();
        let catch_up = server
            .clients
            .replay_entries_since_in_server_for_client(
                &server_id,
                &self.last_client_versions,
                &self.last_client_epochs,
                self.client.get_session_id(),
                self.client.client_instance_id(),
            )
            .await;
        let (rebases, missed, target_versions, target_epochs) = catch_up.into_parts();
        let mut recovery_reason = trigger_reason;
        let mut projected_users: usize = 0;

        let result = async {
            for rebase in rebases {
                let (origin, _version, epoch, entries) = rebase.into_parts();
                let had_cursor = self.last_client_versions.contains_key(&origin)
                    || self.last_client_epochs.contains_key(&origin);
                if had_cursor && self.last_client_epochs.get(&origin).copied() != epoch {
                    recovery_reason = Some(ClientProjectionRecoveryReason::EpochChange);
                } else if !matches!(
                    recovery_reason,
                    Some(ClientProjectionRecoveryReason::EpochChange)
                ) {
                    recovery_reason = Some(ClientProjectionRecoveryReason::SnapshotFloor);
                }
                projected_users = projected_users.saturating_add(entries.len());

                self.append_origin_reset(server, origin, outbound).await;
                for entry in entries {
                    if should_skip_client_add_entry(
                        &entry.op,
                        self.client.get_session_id(),
                        self.client.client_instance_id(),
                        &self.session_channel_shadow,
                    ) {
                        continue;
                    }
                    self.append_client_entry(server, &entry, outbound).await?;
                }
            }

            for entry in missed {
                if should_skip_client_add_entry(
                    &entry.op,
                    self.client.get_session_id(),
                    self.client.client_instance_id(),
                    &self.session_channel_shadow,
                ) {
                    continue;
                }
                self.append_client_entry(server, &entry, outbound).await?;
            }
            self.last_client_versions = target_versions
                .into_iter()
                .filter(|(_, version)| *version != 0)
                .collect();
            self.last_client_epochs = target_epochs;
            Ok(())
        }
        .await;

        if let Some(reason) = recovery_reason {
            let outcome = if result.is_ok() {
                ClientProjectionRecoveryOutcome::Recovered
            } else {
                ClientProjectionRecoveryOutcome::Failed
            };
            record_client_projection_recovery(
                reason,
                outcome,
                started_at.elapsed(),
                projected_users,
            );
        }

        result
    }
}

#[async_trait]
impl ShardedSubscriber<ClientProjectionEvent> for ClientProjectionState {
    type Output = OwnedMessageBatch;
    type Error = HandleIncomingConnectionError;

    async fn on_registered(&mut self) -> Result<Option<Self::Output>, Self::Error> {
        // The baseline and its cursors were captured before ownership moved to
        // this shard. Catch both logs up before registration is acknowledged.
        self.replay_channel_log = true;
        self.replay_client_log = true;
        self.client_recovery_reason = Some(ClientProjectionRecoveryReason::Registration);
        let mut outbound = Vec::new();
        self.resynchronize(&mut outbound).await?;
        let server = self.server()?;
        if self.baseline_visibility_generation != Some(server.visibility_generation()) {
            let messages = crate::client::visibility::visibility_config_reload_messages(
                &server,
                &self.client,
                &mut self.user_visibility,
                &mut self.channel_tree_shadow,
                &mut self.session_channel_shadow,
            )
            .await;
            outbound.extend(
                crate::channel_handler::suppress_known_projected_permission_messages(
                    messages,
                    &mut self.channel_permission_shadow,
                ),
            );
        }
        Ok((!outbound.is_empty()).then(|| OwnedMessageBatch::new(outbound)))
    }

    async fn handle(&mut self, event: &ClientProjectionEvent) -> Result<Self::Output, Self::Error> {
        let result = async {
            match event {
                ClientProjectionEvent::ClientLagged(skipped) => {
                    tracing::warn!(
                        session = u32::from(self.client.get_session_id()),
                        skipped,
                        "client projection event bridge lagged; replaying immediately"
                    );
                    self.replay_client_log = true;
                    self.client_recovery_reason = Some(ClientProjectionRecoveryReason::RouterLag);
                }
                ClientProjectionEvent::ChannelLagged(skipped) => {
                    tracing::warn!(
                        session = u32::from(self.client.get_session_id()),
                        skipped,
                        "channel projection event bridge lagged; replaying immediately"
                    );
                    self.replay_channel_log = true;
                    self.reconcile_root_channel = true;
                }
                _ => {}
            }

            let server = self.server()?;
            let mut outbound = Vec::new();
            self.resynchronize(&mut outbound).await?;
            match event {
                ClientProjectionEvent::Channel(operation) => {
                    self.append_channel_operation(&server, operation, &mut outbound)
                        .await?;
                }
                ClientProjectionEvent::Client(broadcast) => {
                    self.append_client_broadcast(&server, broadcast, &mut outbound)
                        .await?;
                }
                ClientProjectionEvent::VisibilityReload => {
                    let messages = crate::client::visibility::visibility_config_reload_messages(
                        &server,
                        &self.client,
                        &mut self.user_visibility,
                        &mut self.channel_tree_shadow,
                        &mut self.session_channel_shadow,
                    )
                    .await;
                    outbound.extend(
                        crate::channel_handler::suppress_known_projected_permission_messages(
                            messages,
                            &mut self.channel_permission_shadow,
                        ),
                    );
                }
                ClientProjectionEvent::ClientLagged(_)
                | ClientProjectionEvent::ChannelLagged(_) => {}
            }
            Ok(OwnedMessageBatch::new(outbound))
        }
        .await;
        if result.is_err() {
            self.client.request_disconnect();
        }
        result
    }

    fn deliver(&self, output: Self::Output) -> DeliverResult {
        match self.client.try_write_owned_message_batch(output) {
            Ok(()) => DeliverResult::Delivered,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // A full queue cannot be awaited by a shard. Disconnecting is
                // conservative and bounds both memory and head-of-line delay.
                record_client_projection_disconnect(
                    ClientProjectionDisconnectReason::WriterQueueFull,
                );
                self.client.request_disconnect();
                DeliverResult::Remove
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                record_client_projection_disconnect(
                    ClientProjectionDisconnectReason::WriterQueueClosed,
                );
                self.client.request_disconnect();
                DeliverResult::Remove
            }
        }
    }

    fn on_remove(&self) {
        self.client.request_disconnect();
    }

    fn on_lag(&mut self, skipped: u64) -> LagAction {
        tracing::warn!(
            session = u32::from(self.client.get_session_id()),
            skipped,
            "projection shard event log lagged; recovering merged state"
        );
        self.replay_client_log = true;
        self.replay_channel_log = true;
        self.reconcile_root_channel = true;
        self.client_recovery_reason = Some(ClientProjectionRecoveryReason::ShardLag);
        LagAction::Keep
    }

    async fn recover_lag(&mut self) -> Result<Option<Self::Output>, Self::Error> {
        let mut outbound = Vec::new();
        // The merged shard stream can contain visibility notifications as well
        // as client and channel operations. Apply current visibility first so
        // replay cannot transiently disclose state hidden by a skipped reload.
        let server = self.server()?;
        let messages = crate::client::visibility::visibility_config_reload_messages(
            &server,
            &self.client,
            &mut self.user_visibility,
            &mut self.channel_tree_shadow,
            &mut self.session_channel_shadow,
        )
        .await;
        outbound.extend(
            crate::channel_handler::suppress_known_projected_permission_messages(
                messages,
                &mut self.channel_permission_shadow,
            ),
        );
        self.resynchronize(&mut outbound).await?;

        Ok((!outbound.is_empty()).then(|| OwnedMessageBatch::new(outbound)))
    }
}

fn merge_one_version(versions: &mut HashMap<u16, u64>, node_id: u16, version: u64) {
    if version == 0 {
        versions.remove(&node_id);
    } else {
        let current = versions.entry(node_id).or_default();
        *current = (*current).max(version);
    }
}

fn merge_version_vector(current: &mut HashMap<u16, u64>, updates: &HashMap<u16, u64>) {
    for (&node_id, &version) in updates {
        merge_one_version(current, node_id, version);
    }
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

fn should_skip_client_add_entry(
    operation: &ClientStateOperation,
    viewer_session_id: ClientSessionIdentifier,
    viewer_client_instance_id: ClientInstanceId,
    session_channel_shadow: &SessionChannelShadow,
) -> bool {
    matches!(
        operation,
        ClientStateOperation::AddClient {
            session_id,
            client_instance_id,
            ..
        } if *session_id == viewer_session_id && *client_instance_id == viewer_client_instance_id
            || session_channel_shadow.contains_key(session_id)
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::*;
    use crate::client_repository::ClientRepository;

    fn ping(timestamp: u64) -> Message {
        shitspeak_messages::messages::encoder::Ping::default_from_timestamp(timestamp).into()
    }

    fn projection_for_delivery(client: Arc<Box<Client>>) -> ClientProjectionState {
        ClientProjectionState::new(
            Weak::new(),
            client,
            ChannelTreeShadow::new(),
            SessionChannelShadow::new(),
            UserVisibilityState::default(),
            HashMap::new(),
            HashMap::new(),
            0,
        )
    }

    #[test]
    fn version_vector_merge_is_monotonic_and_zero_resets_an_origin() {
        let mut current = HashMap::from([(1, 7), (2, 3)]);
        merge_version_vector(&mut current, &HashMap::from([(1, 5), (2, 9), (3, 4)]));
        assert_eq!(current, HashMap::from([(1, 7), (2, 9), (3, 4)]));

        merge_version_vector(&mut current, &HashMap::from([(1, 0)]));
        assert!(!current.contains_key(&1));
    }

    #[test]
    fn origin_reset_removes_only_sessions_owned_by_that_node() {
        let node_one_a = ClientSessionIdentifier::new(1, 10).expect("valid session");
        let node_one_b = ClientSessionIdentifier::new(1, 11).expect("valid session");
        let node_two = ClientSessionIdentifier::new(2, 10).expect("valid session");
        let mut shadow = SessionChannelShadow::new();
        shadow.insert(node_one_a, 1);
        shadow.insert(node_one_b, 2);
        shadow.insert(node_two, 3);

        let mut removed = take_origin_sessions_from_shadow(&mut shadow, 1);
        removed.sort_unstable_by_key(|session| u32::from(*session));
        assert_eq!(removed, vec![node_one_a, node_one_b]);
        assert_eq!(shadow.get(&node_two), Some(&3));
    }

    #[tokio::test]
    async fn shard_lag_keeps_projection_and_marks_both_logs_for_replay() {
        let repo = ClientRepository::new(1, 16);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let local = SocketAddr::new(ip, 64738);
        let (output_tx, _output_rx) = tokio::sync::mpsc::channel(1);
        let client = repo
            .allocate_web_client_in_server(
                crate::types::DEFAULT_SERVER_ID,
                ip,
                SocketAddr::new(ip, 30000),
                local,
                output_tx,
            )
            .await;
        let mut projection = projection_for_delivery(client);

        assert_eq!(projection.on_lag(7), LagAction::Keep);
        assert!(projection.replay_client_log);
        assert!(projection.replay_channel_log);
    }

    #[tokio::test]
    async fn full_gateway_queue_removes_projection_without_blocking_next_client() {
        let repo = ClientRepository::new(1, 16);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let local = SocketAddr::new(ip, 64738);
        let (slow_tx, mut slow_rx) = tokio::sync::mpsc::channel(1);
        let (fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(1);
        let slow_client = repo
            .allocate_web_client_in_server(
                crate::types::DEFAULT_SERVER_ID,
                ip,
                SocketAddr::new(ip, 30001),
                local,
                slow_tx.clone(),
            )
            .await;
        let fast_client = repo
            .allocate_web_client_in_server(
                crate::types::DEFAULT_SERVER_ID,
                ip,
                SocketAddr::new(ip, 30002),
                local,
                fast_tx,
            )
            .await;
        let slow_projection = projection_for_delivery(Arc::clone(&slow_client));
        let fast_projection = projection_for_delivery(fast_client);

        slow_tx
            .try_send(ping(99))
            .expect("the slow gateway queue should start with one free slot");

        assert_eq!(
            slow_projection.deliver(OwnedMessageBatch::new(vec![ping(1)])),
            DeliverResult::Remove,
            "a full writer queue must remove the subscriber instead of stalling its shard"
        );
        assert_eq!(
            fast_projection.deliver(OwnedMessageBatch::new(vec![ping(2)])),
            DeliverResult::Delivered,
            "the next client handled by the shard must still make progress"
        );

        tokio::time::timeout(Duration::from_secs(1), slow_client.disconnected())
            .await
            .expect("writer backpressure should request connection teardown");
        assert!(matches!(
            slow_rx.try_recv(),
            Ok(Message::Ping(message)) if message.timestamp == Some(99)
        ));
        assert!(matches!(
            slow_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            fast_rx.try_recv(),
            Ok(Message::Ping(message)) if message.timestamp == Some(2)
        ));
    }
}
