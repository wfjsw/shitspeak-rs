use std::sync::Arc;

use bytes::Bytes;

use crate::{
    api::{AuthenticateAuxiliaryData, AuthenticationRejection},
    channel_handler::build_channel_state_message,
    client::{Client, user_info::Credential},
    errors::{AuthRejection, MessageHandlerError},
    localization::{TextKey, text},
    messages::{
        Message, WriteMessageExt,
        encoder::{Authenticate, ChannelState, CodecVersion, RejectType, ServerConfig, ServerSync},
    },
    server::Server,
};

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

    // ── Authentication context and language ───────────────────────────────
    let certificate_hash = sender.get_certificate_hash().map(Bytes::copy_from_slice);
    let mut session_id = sender.get_session_id();
    let ip_address = sender.get_real_ip_address();
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
        ip_address,
        tls_ja4: sender.tls_ja4().map(ToOwned::to_owned),
        uses_proxy_protocol: sender.uses_proxy_protocol(),
        version,
        client_name,
        os_name,
        os_version,
    };
    let pre_auth_language = server
        .get_authenticator()
        .language(Some(username.as_str()), &auth_auxiliary)
        .await;
    sender.set_language(pre_auth_language);

    // ── Certificate required ──────────────────────────────────────────────
    if server.get_cert_required() && !sender.has_certificate() {
        return Err(
            AuthRejection::new_with_language(RejectType::NoCertificate, sender.language()).into(),
        );
    }

    // ── Authenticate ──────────────────────────────────────────────────────
    let auth_result = server
        .get_authenticator()
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
                let hash = match server.get_authenticator().get_user_texture(user_id).await {
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
                let hash = match server.get_authenticator().get_user_comment(user_id).await {
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

    // ── Store identity on client (single transaction) ─────────────────────
    {
        sender.set_language(result.language);
        sender.set_max_bandwidth(result.max_bandwidth);
        let mut gs = sender.write_global_state(repo);
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
        if !root_perms.contains(crate::acl::ACLPermissions::Traverse) {
            tracing::trace!(
                session = u32::from(session),
                "Authenticate built outbound Reject payload"
            );
            return Err(AuthRejection::new(RejectType::None)
                .because(text(sender.language(), TextKey::NoRootTraverse))
                .into());
        }
    }

    // ── Generate crypt state and send CryptSetup ──────────────────────────
    if let Err(e) = sender.create_crypt_state("OCB2-AES128") {
        tracing::error!(session = u32::from(session), error = %e, "Failed to create crypt state");
        return Err(AuthRejection::new(RejectType::None)
            .because(text(sender.language(), TextKey::CryptSetupFailed))
            .into());
    }

    let crypt_setup_msg: Message = {
        let crypt = sender.crypt_state();
        let state = crypt.as_ref().expect("crypt state just created");
        crate::messages::encoder::CryptSetup::new(
            state.key().map(Bytes::copy_from_slice),
            Some(Bytes::copy_from_slice(state.decrypt_iv())),
            Some(Bytes::copy_from_slice(state.encrypt_iv())),
        )
        .into()
    };

    // ── Place user in cached/default channel ─────────────────────────────
    {
        let restored_channels = crate::user_channel_cache::resolve_login_channels(
            server,
            sender,
            channel_cache_key.as_deref(),
        )
        .await;
        let target_ch = restored_channels.current_channel_id;
        sender.set_current_channel_id(
            target_ch,
            repo,
            server.get_channels().current_version_in_server(&server_id),
        );
        let initial_perms =
            crate::client::acl::compute_permissions_for_client(server, sender, target_ch).await;
        {
            let mut gs = sender.write_global_state(repo);
            for channel_id in &restored_channels.listening_channel_ids {
                gs.listen_channel(*channel_id);
            }
            gs.set_suppress(!initial_perms.contains(crate::acl::ACLPermissions::Speak));
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
    // All of the following are sent to the joining client in a single batch
    // write to avoid per-message syscall overhead:
    //
    //   1. CryptSetup
    //   2. ChannelState × N  (BFS channel tree)
    //   3. UserState × M     (all currently authenticated clients)
    //   4. UserState (self)
    //   5. ServerSync
    //   6. ServerConfig
    //   7. CodecVersion
    //
    // This matches the Mumble server's auth-complete sequence.

    let (all_clients, all_versions, client_state_rx) = server
        .get_clients()
        .snapshot_with_versions_and_subscription_in_server(&server_id)
        .await;
    sender.stage_client_state_subscription(client_state_rx);
    let (all_channels, channel_version, channel_state_rx) = server
        .get_channels()
        .snapshot_with_version_and_subscription_in_server(&server_id);
    sender.stage_channel_state_subscription(channel_version, channel_state_rx);

    let mut burst: Vec<Message> = Vec::new();
    let mut push_burst = |message: Message| {
        tracing::trace!(session = u32::from(session_id), message = %message, "Authenticate built outbound message");
        burst.push(message);
    };

    // 1. CryptSetup
    push_burst(crypt_setup_msg);

    // 2. Channel tree — BFS from root
    {
        // BFS ordering: root first, then children in order
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(0u32); // root channel id
        // Map id -> channel for quick lookup
        let ch_map: std::collections::HashMap<u32, _> =
            all_channels.into_iter().map(|c| (c.id, c)).collect();

        let mut visited = std::collections::HashSet::new();
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) {
                continue;
            }
            let Some(ch) = ch_map.get(&id) else { continue };
            let cs = build_channel_state_message(server, sender, ch).await;
            push_burst(cs.into());
            // Enqueue children
            for child in ch_map.values().filter(|c| c.parent_id == Some(id)) {
                queue.push_back(child.id);
            }
        }
    }

    // 3. UserState for every currently authenticated client (excluding self)
    {
        for client in &all_clients {
            if client.get_session_id() == session_id {
                continue;
            }
            if client.server_id() != server_id {
                continue;
            }
            if !client.is_authenticated() {
                continue;
            }
            if !crate::client::visibility::can_view_user(server, sender, client).await {
                continue;
            }
            let us: Message =
                crate::client::visibility::build_visible_user_state(server, sender, client)
                    .await
                    .into();
            push_burst(us);
        }
    }

    // 4. UserState for self
    {
        let self_us: Message =
            crate::client::visibility::build_visible_user_state(server, sender, sender)
                .await
                .into();
        push_burst(self_us);
    }

    // 5. ServerSync
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

    // 6. ServerConfig
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

    // 7. CodecVersion — advertise Opus-only (OCB2-AES128 encrypted voice)
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
    sender.write_proto_message_batch(&burst).await?;

    // ── Mark as authenticated ─────────────────────────────────────────────
    sender.set_authenticated(true);
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

    // ── Spawn per-user TCP voice send task ────────────────────────────────
    crate::voice::spawn_voice_tcp_task(Arc::clone(sender));

    // ── Record last-seen versions so the client doesn't replay old entries ─
    sender.update_last_client_versions(&all_versions).await;

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
