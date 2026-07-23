use std::sync::Arc;

use bytes::Bytes;

use crate::{
    channel_handler::{
        ChannelTreeShadow, SessionChannelShadow, build_visible_channel_snapshot_messages,
    },
    client::{Client, OwnedMessageBatch, user_info::Credential},
    errors::{AuthRejection, MessageHandlerError},
    localization::{TextKey, text},
    messages::{
        Message,
        encoder::{Authenticate, CodecVersion, RejectType, ServerConfig, ServerSync},
    },
    server::Server,
};
use shitspeak_auth::{
    AuthenticateAuxiliaryData, AuthenticationRejection, canonical_authenticator_ip,
};

const AUTH_FINALIZATION_YIELD_EVERY: usize = 64;

pub async fn handle_authenticate(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: Authenticate,
) -> Result<(), MessageHandlerError> {
    let repo = server.get_clients();
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
    if server.get_cert_required() && !sender.has_certificate() {
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
    let channel_cache_key =
        crate::user_channel_cache::user_channel_cache_key(result.user_id, Some(username.as_str()));

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

    // ── Snapshot clients for the selected server scope for max-users.
    let (limit_clients, _) = server
        .get_clients()
        .snapshot_with_versions_in_server(&server_id)
        .await;

    // ── Max-users check ───────────────────────────────────────────────────
    {
        let authenticated_clients = limit_clients
            .iter()
            .filter(|client| client.is_authenticated())
            .count() as u64;
        if authenticated_clients >= server.get_max_users() {
            return Err(AuthRejection::new_with_language(
                RejectType::ServerFull,
                sender.language(),
            )
            .into());
        }
    }

    // ── Required groups check ─────────────────────────────────────────────
    {
        let required = server.get_required_groups();
        if !required.is_empty() {
            let user_groups = result
                .groups
                .iter()
                .map(|s| s.as_str())
                .collect::<std::collections::HashSet<_>>();
            let has_required = required.iter().any(|g| user_groups.contains(g.as_str()));
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

    let (texture_url, texture_hash) = match result.texture_url {
        Some(url) => {
            let hash = server
                .get_session_blobs()
                .fetch_and_cache(&url)
                .await
                .map(|(hash, _)| hash);
            (Some(url), hash)
        }
        None => match result.user_id {
            Some(user_id) => {
                let hash = match auth_permit.authenticator().get_user_texture(user_id).await {
                    Some(texture) if !texture.is_empty() => server
                        .get_session_blobs()
                        .put_content(&texture)
                        .await
                        .map_err(|e| {
                            tracing::warn!(
                                error = %e,
                                user_id,
                                "failed to cache authenticator texture blob"
                            );
                            e
                        })
                        .ok(),
                    _ => None,
                };
                (None, hash)
            }
            None => (None, None),
        },
    };
    let (comment_url, comment_hash) = match result.comment_url {
        Some(url) => {
            let hash = server
                .get_session_blobs()
                .fetch_and_cache(&url)
                .await
                .map(|(hash, _)| hash);
            (Some(url), hash)
        }
        None => match result.user_id {
            Some(user_id) => {
                let hash = match auth_permit.authenticator().get_user_comment(user_id).await {
                    Some(comment) if !comment.is_empty() => server
                        .get_session_blobs()
                        .put_content(comment.as_bytes())
                        .await
                        .map_err(|e| {
                            tracing::warn!(
                                error = %e,
                                user_id,
                                "failed to cache authenticator comment blob"
                            );
                            e
                        })
                        .ok(),
                    _ => None,
                };
                (None, hash)
            }
            None => (None, None),
        },
    };

    // ── Store identity on client ─────────────────────────────────────────
    {
        sender.set_max_bandwidth(result.max_bandwidth);
        let mut gs = sender.write_global_state_direct();
        gs.set_user_id(result.user_id);
        gs.set_display_name(result.display_name);
        gs.set_superuser(result.is_superuser);
        gs.set_groups(result.groups.into_iter().collect());
        gs.set_texture_blob(texture_url, texture_hash);
        gs.set_comment_blob(comment_url, comment_hash);
        // Set access tokens within the same guard
        gs.set_tokens(msg.tokens.into_iter().collect());
    }
    {
        let mut ext = sender.user_info_extended().await;
        ext.set_credential(Credential::new(username, password));
    }

    // ── Traverse permission check on root channel ─────────────────────────
    // Superusers bypass this check.
    if !sender.is_superuser() {
        let root_perms =
            crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
        if !root_perms.contains(shitspeak_state::ACLPermissions::Traverse) {
            tracing::trace!(
                session = u32::from(session),
                "Authenticate built outbound Reject payload"
            );
            return Err(AuthRejection::new(RejectType::None)
                .because(text(sender.language(), TextKey::NoRootTraverse))
                .into());
        }
    }

    sender.complete_authentication(
        auth_session_id,
        authenticated_until,
        authentication_expiry_action,
    );

    // ── Place user in cached/default channel ─────────────────────────────
    {
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
        if let Some(cache_key) = channel_cache_key.as_deref() {
            if let Err(error) = server
                .get_user_channel_cache()
                .remember_last_channel(cache_key, target_ch)
                .await
            {
                tracing::warn!(
                    error = %error,
                    cache_key,
                    "failed to stage user last channel cache"
                );
            }
            if !restored_channels.listening_channel_ids.is_empty() {
                if let Err(error) = server
                    .get_user_channel_cache()
                    .remember_listening_channels(
                        cache_key,
                        restored_channels.listening_channel_ids.iter().copied(),
                    )
                    .await
                {
                    tracing::warn!(
                        error = %error,
                        cache_key,
                        "failed to stage user listening channel cache"
                    );
                }
            }
        }
    }

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
    let (all_clients, all_versions, client_state_rx) = server
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
        for message in build_visible_channel_snapshot_messages(
            server,
            sender,
            &all_channels,
            &mut channel_tree_shadow,
            server.get_send_permission_info(),
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
                max_bandwidth: Some(sender.max_bandwidth(server.get_max_bandwidth())),
                welcome_text: server.get_welcome_text(),
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
                allow_html: Some(server.get_allow_html()),
                message_length: Some(server.get_max_text_message_length()),
                image_message_length: Some(server.get_max_image_message_length()),
                max_users: Some(server.get_max_users() as u32),
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
    sender
        .write_owned_message_batch(OwnedMessageBatch::new(burst))
        .await?;

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
    sender.update_last_client_versions(&all_versions).await;

    // Store Opus support flag for codec negotiation
    {
        let mut local = sender.write_local_state();
        if let Some(ref mut state) = *local {
            state.set_supports_opus(msg.opus.unwrap_or(false));
        }
    }

    drop(auth_permit);

    // The AddClient log entry (emitted by allocate_local_client) will drive
    // the UserState broadcast to all existing per-client subscribers.
    // No need to broadcast manually here.

    Ok(())
}
