use std::sync::Arc;

use bytes::Bytes;

use crate::{
    channel_handler::{
        ChannelTreeShadow, SessionChannelShadow, build_visible_ordered_channel_snapshot_messages,
    },
    client::{Client, DeferredSessionBlobResolution, OwnedMessageBatch, user_info::Credential},
    errors::{AuthRejection, MessageHandlerError},
    localization::{TextKey, text},
    messages::{
        Message,
        encoder::{Authenticate, CodecVersion, RejectType, ServerConfig, ServerSync},
    },
    server::Server,
};
use shitspeak_auth::{
    AuthenticateAuxiliaryData, AuthenticationRejection, Authenticator, canonical_authenticator_ip,
};

const AUTH_FINALIZATION_YIELD_EVERY: usize = 64;

struct StagedUserChannelCacheWrite {
    cache_key: String,
    current_channel_id: u32,
    listening_channel_ids: Vec<u32>,
}

pub async fn handle_authenticate(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: Authenticate,
) -> Result<(), MessageHandlerError> {
    let repo = server.get_clients();
    // Keep authentication policy and advertised limits coherent even if a
    // configuration reload completes while this login is queued.
    let auth_config = server.read_config();
    let mut session = sender.get_session_id();
    let provisional_server_id = sender.server_id();
    tracing::debug!(
        session = u32::from(session),
        username = msg.username,
        has_password = msg.password.is_some(),
        tokens = msg.tokens.len(),
        "Authenticate handler"
    );

    // An expiry-triggered reauthentication owns the credential exchange.
    // Ignore client Authenticate messages until that bounded backend call
    // completes so they cannot start a second full login path concurrently.
    if sender.is_reauthentication_in_progress() {
        tracing::debug!(
            session = u32::from(session),
            "ignoring Authenticate while server reauthentication is in progress"
        );
        return Ok(());
    }

    // ── Token-update path ─────────────────────────────────────────────────
    // An already-authenticated client can send Authenticate again to update
    // its access tokens.
    if sender.is_authenticated() {
        tracing::debug!(
            session = u32::from(session),
            "Authenticate: token update for already-authenticated client"
        );
        let token_count = msg.tokens.len();
        sender.set_tokens(msg.tokens.into_iter().collect(), repo);
        tracing::info!(
            server_id = %sender.server_id(),
            session = u32::from(sender.get_session_id()),
            user_id = ?sender.get_user_id(),
            display_name = ?sender.display_name_opt(),
            token_count,
            "client re-authenticated"
        );
        return Ok(());
    }

    // ── Username required ─────────────────────────────────────────────────
    let username = msg.username.ok_or(RejectType::InvalidUsername)?;
    let password = msg.password;

    // ── Authentication context ────────────────────────────────────────────
    let certificate_hash = sender.get_certificate_hash().map(Bytes::copy_from_slice);
    let mut session_id = sender.get_session_id();
    let ip_address = canonical_authenticator_ip(sender.get_real_ip_address());
    let (version, client_name, os_name, os_version) = {
        let protocol_version = sender.protocol_version();
        let local_state = sender.read_local_state();
        let local = local_state
            .as_ref()
            .expect("Local state missing during authenticate");
        (
            protocol_version,
            local.get_release().map(|s| s.to_owned()),
            local.get_os_name().map(|s| s.to_owned()),
            local.get_os_version().map(|s| s.to_owned()),
        )
    };
    let auth_auxiliary = AuthenticateAuxiliaryData {
        certificate_hash,
        session_id: session_id.into(),
        auth_session_id: None,
        ip_address,
        tls_ja4: sender.tls_ja4().map(ToOwned::to_owned),
        uses_proxy_protocol: sender.uses_proxy_protocol(),
        version,
        client_name,
        os_name,
        os_version,
    };
    // ── Certificate required ──────────────────────────────────────────────
    if auth_config.cert_required && !sender.has_certificate() {
        return Err(
            AuthRejection::new_with_language(RejectType::NoCertificate, sender.language()).into(),
        );
    }

    // Send CryptSetup before auth finalization can queue. Native clients start
    // probing encrypted UDP as soon as they have keys; if this waits behind the
    // login queue they can falsely latch onto TCP voice for several seconds.
    let crypt_setup_msg: Message = {
        let needs_crypt_state = sender.crypt_state().is_none();
        if needs_crypt_state {
            if let Err(e) = server
                .create_client_crypt_state(sender, "OCB2-AES128")
                .await
            {
                tracing::error!(
                    session = u32::from(session),
                    error = %e,
                    "Failed to create crypt state"
                );
                return Err(AuthRejection::new(RejectType::None)
                    .because(text(sender.language(), TextKey::CryptSetupFailed))
                    .into());
            }
        }

        let crypt = sender.crypt_state();
        let state = crypt.as_ref().expect("crypt state just created");
        shitspeak_messages::messages::encoder::CryptSetup::new(
            state.key().map(Bytes::copy_from_slice),
            Some(Bytes::copy_from_slice(state.decrypt_iv())),
            Some(Bytes::copy_from_slice(state.encrypt_iv())),
        )
        .into()
    };
    sender.write_proto_message(&crypt_setup_msg).await?;

    let auth_permit = server.acquire_auth_finalization_permit(sender).await?;

    // ── Authenticate ──────────────────────────────────────────────────────
    let auth_result = auth_permit
        .authenticator()
        .authenticate(&username, password.as_deref(), &auth_auxiliary)
        .await;

    let result = match auth_result {
        Ok(r) => r,
        Err(AuthenticationRejection::NoSuchUser) => {
            return Err(AuthRejection::new_with_language(
                RejectType::InvalidUsername,
                sender.language(),
            )
            .into());
        }
        Err(AuthenticationRejection::WrongPassword) => {
            return Err(AuthRejection::new_with_language(
                RejectType::WrongUserPw,
                sender.language(),
            )
            .into());
        }
        Err(AuthenticationRejection::RetryLater) => {
            return Err(AuthRejection::new_with_language(
                RejectType::AuthenticatorFail,
                sender.language(),
            )
            .into());
        }
    };
    if result.user_id == Some(u32::MAX) {
        return Err(AuthRejection::new_with_language(
            RejectType::AuthenticatorFail,
            sender.language(),
        )
        .into());
    }

    let auth_session_id = result.auth_session_id.clone();
    let authenticated_until = result.authenticated_until;
    let authentication_expiry_action = result.authentication_expiry_action;
    sender.set_language(result.language);
    let channel_cache_key = crate::user_channel_cache::user_channel_cache_key(
        result.fqdn.as_deref(),
        result.user_id,
        Some(username.as_str()),
    );
    let legacy_channel_cache_key = result.user_id.map(|user_id| user_id.to_string());

    if let Some(auth_server_id) = result.virtual_server_id.clone() {
        if auth_server_id != provisional_server_id {
            let Some(new_session) = repo
                .move_local_client_to_server(&provisional_server_id, session, &auth_server_id)
                .await
            else {
                return Err(AuthRejection::new_with_language(
                    RejectType::ServerFull,
                    sender.language(),
                )
                .into());
            };
            session = new_session;
            session_id = new_session;
        }
    }
    let server_id = sender.server_id();

    // Avoid identity/ACL finalization work when the selected server is
    // already full. The reservation CAS below remains the race-safe check.
    if repo.authenticated_client_count_in_server(&server_id) >= auth_config.max_users {
        return Err(
            AuthRejection::new_with_language(RejectType::ServerFull, sender.language()).into(),
        );
    }

    // ── Required groups check ─────────────────────────────────────────────
    {
        if !auth_config.required_groups.is_empty() {
            let has_required = result
                .groups
                .iter()
                .any(|group| auth_config.required_groups.contains(group));
            if !has_required {
                tracing::trace!(
                    session = u32::from(session),
                    "Authenticate built outbound Reject payload"
                );
                return Err(AuthRejection::new(RejectType::None)
                    .because(text(sender.language(), TextKey::MissingRequiredGroup))
                    .into());
            }
        }
    }

    let initial_texture_url = result.texture_url.clone();
    let initial_comment_url = result.comment_url.clone();

    // ── Store identity on client ─────────────────────────────────────────
    {
        sender.set_max_bandwidth(result.max_bandwidth);
        let mut gs = sender.write_global_state_direct();
        gs.set_user_id(result.user_id);
        gs.set_fqdn(result.fqdn);
        gs.set_display_name(result.display_name);
        gs.set_superuser(result.is_superuser);
        gs.set_groups(result.groups.into_iter().collect());
        gs.set_texture_blob(initial_texture_url, None);
        gs.set_comment_blob(initial_comment_url, None);
        // Set access tokens within the same guard
        gs.set_tokens(msg.tokens.into_iter().collect());
    }
    {
        let mut ext = sender.user_info_extended().await;
        ext.set_credential(Credential::new(username, password));
    }

    // Reserve before the root ACL check so concurrent over-capacity attempts
    // do not all perform the same permission computation. Replicated counts
    // remain eventually consistent across cluster nodes.
    if !repo
        .try_reserve_authenticated_client_in_server(
            &server_id,
            sender.get_session_id(),
            auth_config.max_users,
        )
        .await
    {
        return Err(
            AuthRejection::new_with_language(RejectType::ServerFull, sender.language()).into(),
        );
    }

    // ── Traverse permission check on root channel ─────────────────────────
    // Superusers bypass this check.
    if !sender.is_superuser() {
        let root_perms =
            crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
        if !root_perms.contains(shitspeak_state::ACLPermissions::Traverse) {
            repo.release_authenticated_client_reservation_in_server(
                &server_id,
                sender.get_session_id(),
            )
            .await;
            tracing::trace!(
                session = u32::from(session),
                "Authenticate built outbound Reject payload"
            );
            return Err(AuthRejection::new(RejectType::None)
                .because(text(sender.language(), TextKey::NoRootTraverse))
                .into());
        }
    }
    sender.stage_session_blob_resolution(result.user_id, result.texture_url, result.comment_url);
    sender.complete_authentication(
        auth_session_id,
        authenticated_until,
        authentication_expiry_action,
    );

    // ── Place user in cached/default channel ─────────────────────────────
    let staged_channel_cache_write = {
        if let (Some(legacy_key), Some(cache_key)) = (
            legacy_channel_cache_key.as_deref(),
            channel_cache_key.as_deref(),
        ) {
            if let Err(error) = server
                .get_user_channel_cache()
                .migrate_key(legacy_key, cache_key)
                .await
            {
                tracing::warn!(
                    error = %error,
                    legacy_key,
                    cache_key,
                    "failed to migrate user channel cache identity"
                );
            }
        }
        let restored_channels = crate::user_channel_cache::resolve_login_channels(
            server,
            sender,
            channel_cache_key.as_deref(),
        )
        .await;
        let target_ch = restored_channels.current_channel_id;
        {
            let previous_channel_id = sender.get_current_channel_id();
            let mut gs = sender.write_global_state_direct();
            if gs.set_current_channel_id(target_ch) {
                tracing::info!(
                    server_id = %sender.server_id(),
                    session = u32::from(sender.get_session_id()),
                    user_id = ?gs.get_user_id(),
                    display_name = ?gs.get_display_name_opt(),
                    previous_channel_id,
                    channel_id = target_ch,
                    "client entered channel"
                );
            }
        }
        let initial_perms = crate::client::acl::compute_permissions_for_client_as_if_in_channel(
            server, sender, target_ch,
        )
        .await;
        {
            let mut gs = sender.write_global_state_direct();
            for channel_id in &restored_channels.listening_channel_ids {
                gs.listen_channel(*channel_id);
            }
            gs.set_suppress(!initial_perms.contains(shitspeak_state::ACLPermissions::Speak));
        }
        channel_cache_key.map(|cache_key| StagedUserChannelCacheWrite {
            cache_key,
            current_channel_id: target_ch,
            listening_channel_ids: restored_channels.listening_channel_ids,
        })
    };

    // ── Build the full burst of messages to send to the new client ────────
    //
    // CryptSetup was sent before auth finalization so clients waiting in the
    // login queue can prove UDP reachability immediately. The remaining
    // messages are sent to the joining client in a single batch to avoid
    // per-message syscall overhead:
    //
    //   1. ChannelState × N  (BFS channel tree)
    //   2. UserState × M     (all currently authenticated clients)
    //   3. UserState (self)
    //   4. ServerSync
    //   5. ServerConfig
    //   6. CodecVersion
    //
    // This matches the Mumble server's auth-complete sequence after the
    // connection-level UDP crypto has already been established.

    let visibility_generation = server.visibility_generation();
    let (all_clients, all_versions, all_epochs, client_state_rx) = server
        .get_clients()
        .published_snapshot_with_versions_and_subscription_in_server(&server_id)
        .await;
    sender.stage_client_state_subscription(client_state_rx);
    let (all_channels, channel_version, channel_state_rx) = server
        .get_channels()
        .snapshot_with_version_and_subscription_in_server(&server_id);
    sender.stage_channel_state_subscription(channel_version, channel_state_rx);

    let mut channel_tree_shadow = ChannelTreeShadow::new();
    let mut session_channel_shadow = SessionChannelShadow::new();
    let mut user_visibility = crate::client::visibility::UserVisibilityState::default();
    let viewer_independent_user_state =
        crate::client::visibility::user_state_projection_is_viewer_independent(server, sender);

    let mut burst: Vec<Message> = Vec::new();
    let mut push_burst = |message: Message| {
        tracing::trace!(session = u32::from(session_id), message = %message, "Authenticate built outbound message");
        burst.push(message);
    };

    // 1. Channel tree — BFS from root
    {
        for message in build_visible_ordered_channel_snapshot_messages(
            server,
            sender,
            &all_channels,
            &mut channel_tree_shadow,
            auth_config.send_permission_info,
        )
        .await
        {
            push_burst(message);
        }
    }

    // 2. UserState for every published authenticated client (excluding self)
    {
        for (index, client) in all_clients.iter().enumerate() {
            if index != 0 && index % AUTH_FINALIZATION_YIELD_EVERY == 0 {
                // Login snapshots are bulk/background work. Cooperate with the
                // shared runtime so ping and small voice tasks run first.
                tokio::task::yield_now().await;
            }
            if client.get_session_id() == session_id
                && client.client_instance_id() == sender.client_instance_id()
            {
                continue;
            }
            if client.server_id() != server_id {
                continue;
            }
            if !client.is_authenticated() {
                continue;
            }
            if viewer_independent_user_state {
                session_channel_shadow
                    .insert(client.get_session_id(), client.get_current_channel_id());
                user_visibility.remember_projected_user(
                    client.get_session_id(),
                    client.get_current_channel_id(),
                    client.get_listening_channel_ids(),
                );
                push_burst(client.build_user_state_for_broadcast().into());
            } else {
                let us: Message = client.build_user_state_for_broadcast().into();
                let projected = crate::client::visibility::project_message_with_shadow(
                    server,
                    sender,
                    &mut user_visibility,
                    &mut session_channel_shadow,
                    &server_id,
                    &us,
                )
                .await;
                for message in projected {
                    push_burst(message);
                }
            }
        }
    }

    // 3. UserState for self
    {
        session_channel_shadow.insert(session_id, sender.get_current_channel_id());
        if viewer_independent_user_state {
            user_visibility.remember_projected_user(
                session_id,
                sender.get_current_channel_id(),
                sender.get_listening_channel_ids(),
            );
            push_burst(sender.build_user_state_for_broadcast().into());
        } else {
            let self_us: Message = sender.build_user_state_for_broadcast().into();
            let projected = crate::client::visibility::project_message_with_shadow(
                server,
                sender,
                &mut user_visibility,
                &mut session_channel_shadow,
                &server_id,
                &self_us,
            )
            .await;
            for message in projected {
                push_burst(message);
            }
        }
    }

    sender.stage_post_auth_baseline(crate::client::PostAuthBaseline::with_user_visibility(
        session_channel_shadow,
        channel_tree_shadow,
        user_visibility,
        visibility_generation,
    ));

    for action in server.context_actions().build_modify_list().await {
        push_burst(action.into());
    }
    if sender.is_superuser() {
        push_burst(
            crate::toggle_superuser_visibility::action(sender.is_hidden_from_regular_users())
                .into(),
        );
    }

    // 4. ServerSync
    {
        let root_perm = crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
        push_burst(Message::ServerSync(
            ServerSync {
                session: Some(u32::from(session_id)),
                max_bandwidth: Some(sender.max_bandwidth(auth_config.max_bandwidth)),
                welcome_text: auth_config.welcome_text.clone(),
                permissions: Some(root_perm),
            }
            .into(),
        ));
    }

    // 5. ServerConfig
    {
        push_burst(Message::ServerConfig(
            ServerConfig {
                max_bandwidth: None,
                welcome_text: None,
                allow_html: Some(auth_config.allow_html),
                message_length: Some(auth_config.max_text_message_length),
                image_message_length: Some(auth_config.max_image_message_length),
                max_users: Some(auth_config.max_users as u32),
            }
            .into(),
        ));
    }

    // 6. CodecVersion — advertise Opus-only (OCB2-AES128 encrypted voice)
    {
        push_burst(Message::CodecVersion(
            CodecVersion {
                alpha: -2147483637, // CELT alpha version (unused, but required by clients)
                beta: 0,
                prefer_alpha: false,
                opus: Some(true),
            }
            .into(),
        ));
    }

    // ── Send the burst to the joining client in one shot ──────────────────
    // The authentication state and initial sync burst are now finalized. Do
    // not hold an admission slot while waiting for outbound queue capacity.
    drop(auth_permit);

    sender
        .write_owned_message_batch(OwnedMessageBatch::new(burst))
        .await?;

    if let Some(staged) = staged_channel_cache_write {
        if let Err(error) = server
            .get_user_channel_cache()
            .remember_last_channel(&staged.cache_key, staged.current_channel_id)
            .await
        {
            tracing::warn!(
                error = %error,
                cache_key = staged.cache_key,
                "failed to stage user last channel cache"
            );
        }
        if !staged.listening_channel_ids.is_empty() {
            if let Err(error) = server
                .get_user_channel_cache()
                .remember_listening_channels(
                    &staged.cache_key,
                    staged.listening_channel_ids.iter().copied(),
                )
                .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key = staged.cache_key,
                    "failed to stage user listening channel cache"
                );
            }
        }
    }

    tracing::info!(
        server_id = %sender.server_id(),
        session = u32::from(session_id),
        user_id = ?sender.get_user_id(),
        display_name = ?sender.display_name_opt(),
        transport = ?sender.transport_kind(),
        "client authenticated"
    );

    // ── Spawn per-user voice routing task ─────────────────────────────────
    crate::voice::spawn_voice_routing_task(Arc::clone(server), Arc::clone(sender));

    // Native TLS clients have their TCP voice queue drained by the native
    // writer task. Gateway transports do not, so keep the fallback bridge.
    if sender.transport_kind() != crate::client::ClientTransportKind::NativeMumble {
        crate::voice::spawn_voice_tcp_task(Arc::clone(sender));
    }

    // ── Record last-seen versions so the client doesn't replay old entries ─
    sender
        .set_last_client_cursors(all_versions, all_epochs)
        .await;

    // Store Opus support flag for codec negotiation
    {
        let mut local = sender.write_local_state();
        if let Some(ref mut state) = *local {
            state.set_supports_opus(msg.opus.unwrap_or(false));
        }
    }

    // The AddClient log entry (emitted by allocate_local_client) will drive
    // the UserState broadcast to all existing per-client subscribers.
    // No need to broadcast manually here.

    Ok(())
}

pub fn spawn_staged_session_blob_resolution(server: Arc<Box<Server>>, client: Arc<Box<Client>>) {
    if let Some(resolution) = client.take_session_blob_resolution() {
        spawn_deferred_session_blob_resolution(server, client, resolution);
    }
}

fn spawn_deferred_session_blob_resolution(
    server: Arc<Box<Server>>,
    client: Arc<Box<Client>>,
    resolution: DeferredSessionBlobResolution,
) {
    tokio::spawn(async move {
        if !client_is_current(&server, &client).await {
            return;
        }
        let (user_id, texture_url, comment_url, texture_revision, comment_revision) =
            resolution.into_parts();
        let authenticator = server.authenticator_arc();
        let texture = resolve_texture(&server, Arc::clone(&authenticator), user_id, texture_url);
        let comment = resolve_comment(&server, authenticator, user_id, comment_url);
        tokio::pin!(texture);
        tokio::pin!(comment);
        let mut texture_done = false;
        let mut comment_done = false;

        while !texture_done || !comment_done {
            tokio::select! {
                _ = client.removed() => return,
                resolved = &mut texture, if !texture_done => {
                    texture_done = true;
                    apply_resolved_texture(&server, &client, texture_revision, resolved).await;
                }
                resolved = &mut comment, if !comment_done => {
                    comment_done = true;
                    apply_resolved_comment(&server, &client, comment_revision, resolved).await;
                }
            }
        }
    });
}

async fn resolve_texture(
    server: &Arc<Box<Server>>,
    authenticator: Arc<dyn Authenticator>,
    user_id: Option<u32>,
    texture_url: Option<String>,
) -> (Option<String>, Option<String>) {
    match texture_url {
        Some(url) => {
            let hash = server
                .get_session_blobs()
                .fetch_and_cache(&url)
                .await
                .map(|(hash, _)| hash);
            (Some(url), hash)
        }
        None => {
            let hash = match user_id {
                Some(user_id) => match authenticator.get_user_texture(user_id).await {
                    Some(texture) if !texture.is_empty() => server
                        .get_session_blobs()
                        .put_content(&texture)
                        .await
                        .map_err(|error| {
                            tracing::warn!(
                                %error,
                                user_id,
                                "failed to cache authenticator texture blob"
                            );
                            error
                        })
                        .ok(),
                    _ => None,
                },
                None => None,
            };
            (None, hash)
        }
    }
}

async fn resolve_comment(
    server: &Arc<Box<Server>>,
    authenticator: Arc<dyn Authenticator>,
    user_id: Option<u32>,
    comment_url: Option<String>,
) -> (Option<String>, Option<String>) {
    match comment_url {
        Some(url) => {
            let hash = server
                .get_session_blobs()
                .fetch_and_cache(&url)
                .await
                .map(|(hash, _)| hash);
            (Some(url), hash)
        }
        None => {
            let hash = match user_id {
                Some(user_id) => match authenticator.get_user_comment(user_id).await {
                    Some(comment) if !comment.is_empty() => server
                        .get_session_blobs()
                        .put_content(comment.as_bytes())
                        .await
                        .map_err(|error| {
                            tracing::warn!(
                                %error,
                                user_id,
                                "failed to cache authenticator comment blob"
                            );
                            error
                        })
                        .ok(),
                    _ => None,
                },
                None => None,
            };
            (None, hash)
        }
    }
}

async fn apply_resolved_texture(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    expected_revision: u64,
    (url, hash): (Option<String>, Option<String>),
) {
    if !client_is_current(server, client).await
        || !client.is_authenticated()
        || !client.is_published()
    {
        return;
    }
    let mut state = client.write_global_state(server.get_clients());
    apply_texture_if_revision(&mut state, expected_revision, url, hash);
}

async fn apply_resolved_comment(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    expected_revision: u64,
    (url, hash): (Option<String>, Option<String>),
) {
    if !client_is_current(server, client).await
        || !client.is_authenticated()
        || !client.is_published()
    {
        return;
    }
    let mut state = client.write_global_state(server.get_clients());
    apply_comment_if_revision(&mut state, expected_revision, url, hash);
}

fn apply_texture_if_revision(
    state: &mut crate::client::client_global_state::ClientGlobalState,
    expected_revision: u64,
    url: Option<String>,
    hash: Option<String>,
) {
    if state.texture_blob_revision() == expected_revision {
        state.set_texture_blob(url, hash);
    }
}

fn apply_comment_if_revision(
    state: &mut crate::client::client_global_state::ClientGlobalState,
    expected_revision: u64,
    url: Option<String>,
    hash: Option<String>,
) {
    if state.comment_blob_revision() == expected_revision {
        state.set_comment_blob(url, hash);
    }
}

async fn client_is_current(server: &Arc<Box<Server>>, client: &Arc<Box<Client>>) -> bool {
    server
        .get_clients()
        .get_client_in_server(&client.server_id(), client.get_session_id())
        .await
        .is_some_and(|current| Arc::ptr_eq(&current, client))
}

#[cfg(test)]
mod tests {
    use super::{apply_comment_if_revision, apply_texture_if_revision};
    use crate::client::client_global_state::ClientGlobalState;

    #[test]
    fn explicit_clear_blocks_late_authenticator_blobs() {
        let mut state = ClientGlobalState::new();
        let texture_revision = state.texture_blob_revision();
        let comment_revision = state.comment_blob_revision();

        state.clear_texture_blob();
        state.clear_comment_blob();
        apply_texture_if_revision(
            &mut state,
            texture_revision,
            None,
            Some("late-texture".to_owned()),
        );
        apply_comment_if_revision(
            &mut state,
            comment_revision,
            None,
            Some("late-comment".to_owned()),
        );

        assert!(state.get_texture_hash().is_none());
        assert!(state.get_comment_hash().is_none());
    }
}
