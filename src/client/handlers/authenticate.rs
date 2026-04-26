use std::sync::Arc;

use crate::{
    api::{AuthenticateAuxiliaryData, AuthenticationRejection},
    channel_handler::build_channel_state_message,
    client::{Client, user_info::Credential},
    errors::{AuthRejection, MessageHandlerError},
    messages::{Message, WriteMessageExt, encoder::{Authenticate, ChannelState, CodecVersion, RejectType, ServerConfig, ServerSync}},
    server::Server,
};

pub async fn handle_authenticate(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: Authenticate,
) -> Result<(), MessageHandlerError> {
    let repo = server.get_clients();
    let session = sender.get_session_id();
    tracing::debug!(session = u32::from(session), username = msg.username, has_password = msg.password.is_some(), tokens = msg.tokens.len(), "Authenticate handler");

    // ── Token-update path ─────────────────────────────────────────────────
    // An already-authenticated client can send Authenticate again to update
    // its access tokens.
    if sender.is_authenticated().await {
        tracing::debug!(session = u32::from(session), "Authenticate: token update for already-authenticated client");
        sender.set_tokens(msg.tokens.into_iter().collect(), repo).await;
        return Ok(());
    }

    // ── Username required ─────────────────────────────────────────────────
    let username = msg.username.ok_or(RejectType::InvalidUsername)?;
    let password = msg.password;

    // ── Snapshot all clients + versions (used for max-users, UserState
    //     broadcast, and last-seen version tracking) ────────────────────────
    let (all_clients, all_versions) = server.get_clients().snapshot_with_versions().await;

    // ── Max-users check ───────────────────────────────────────────────────
    {
        let n = all_clients.len() as u64;
        if n >= server.get_max_users() {
            return Err(RejectType::ServerFull.into());
        }
    }

    // ── Certificate required ──────────────────────────────────────────────
    if server.get_cert_required() && !sender.has_certificate() {
        return Err(RejectType::NoCertificate.into());
    }

    // ── Authenticate ──────────────────────────────────────────────────────
    let certificate_hash = sender.get_certificate_hash().map(|hash| hash.to_vec());
    let session_id = sender.get_session_id();
    let ip_address = sender.get_real_ip_address();
    let (version, client_name, os_name, os_version) = {
        let global_state = sender.read_global_state().await;
        let local_state = sender.read_local_state().await;
        let local = local_state.as_ref().expect("Local state missing during authenticate");
        (
            global_state.get_protocol_version(),
            local.get_release().map(|s| s.to_owned()),
            local.get_os_name().map(|s| s.to_owned()),
            local.get_os_version().map(|s| s.to_owned()),
        )
    };

    let auth_result = server
        .get_authenticator()
        .authenticate(
            &username,
            password.as_deref(),
            &AuthenticateAuxiliaryData {
                certificate_hash,
                session_id: session_id.into(),
                ip_address,
                version,
                client_name,
                os_name,
                os_version,
            },
        )
        .await;

    let result = match auth_result {
        Ok(r) => r,
        Err(AuthenticationRejection::NoSuchUser) => return Err(RejectType::InvalidUsername.into()),
        Err(AuthenticationRejection::WrongPassword) => return Err(RejectType::WrongUserPw.into()),
        Err(AuthenticationRejection::RetryLater) => {
            return Err(RejectType::AuthenticatorFail.into())
        }
    };

    // ── Required groups check ─────────────────────────────────────────────
    {
        let required = server.get_required_groups();
        if !required.is_empty() {
            let user_groups = result.groups.iter().map(|s| s.as_str()).collect::<std::collections::HashSet<_>>();
            let has_required = required.iter().any(|g| user_groups.contains(g.as_str()));
            if !has_required {
                tracing::trace!(session = u32::from(session), "Authenticate built outbound Reject payload");
                return Err(AuthRejection::new(RejectType::None)
                    .because("Missing required group membership")
                    .into());
            }
        }
    }

    // ── Store identity on client (single transaction) ─────────────────────
    {
        let mut gs = sender.write_global_state(repo).await;
        gs.set_user_id(result.user_id);
        gs.set_display_name(result.display_name);
        gs.set_groups(result.groups.into_iter().collect());
        gs.set_texture_blob(result.texture_url, None);
        gs.set_comment_blob(result.comment_url, None);
        // Set access tokens within the same guard
        gs.set_tokens(msg.tokens.into_iter().collect());
    }
    {
        let mut ext = sender.user_info_extended().await;
        ext.set_credential(Credential::new(username, password));
    }

    // ── Traverse permission check on root channel ─────────────────────────
    // Superusers bypass this check.
    if !sender.is_superuser().await {
        let root_perms = crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
        if !root_perms.contains(crate::acl::ACLPermissions::Traverse) {
            tracing::trace!(session = u32::from(session), "Authenticate built outbound Reject payload");
            return Err(AuthRejection::new(RejectType::None)
                .because("No traverse permission on root channel")
                .into());
        }
    }

    // ── Generate crypt state and send CryptSetup ──────────────────────────
    if let Err(e) = sender
        .create_crypt_state("OCB2-AES128")
        .await {
        tracing::error!(session = u32::from(session), error = %e, "Failed to create crypt state");
        return Err(AuthRejection::new(RejectType::None)
            .because("Failed to create crypt state")
            .into());
    }

    let crypt_setup_msg: Message = {
        let crypt = sender.crypt_state().await;
        let state = crypt.as_ref().expect("crypt state just created");
        crate::messages::encoder::CryptSetup::new(
            state.key().map(|k| k.to_vec()),
            Some(state.encrypt_iv().to_vec()),
            Some(state.decrypt_iv().to_vec()),
        ).into()
    };

    // ── Place user in the default channel ────────────────────────────────
    {
        let default_ch = server.get_default_channel();
        let target_ch = if server.get_channels().get_channel(default_ch).await.is_some() {
            default_ch
        } else {
            0 // fall back to root
        };
        sender.set_current_channel_id(target_ch, repo, server.get_channels().current_version()).await;
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

    let mut burst: Vec<Message> = Vec::new();
    let mut push_burst = |message: Message| {
        tracing::trace!(session = u32::from(session_id), message = %message, "Authenticate built outbound message");
        burst.push(message);
    };

    // 1. CryptSetup
    push_burst(crypt_setup_msg);

    // 2. Channel tree — BFS from root
    {
        let all_channels = server.get_channels().get_all().await;
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
            if !client.is_authenticated().await {
                continue;
            }
            let us: Message = client.build_user_state_for_broadcast().await.into();
            push_burst(us);
        }
    }

    // 4. UserState for self
    {
        let self_us: Message = sender.build_user_state_for_broadcast().await.into();
        push_burst(self_us);
    }

    // 5. ServerSync
    {
        // Effective root permissions for the new user: full for now (TODO: ACL eval)
        let root_perm = 0x0000_FFFF_u32;
        push_burst(Message::ServerSync(ServerSync {
            session: Some(u32::from(session_id)),
            max_bandwidth: Some(server.get_max_bandwidth()),
            welcome_text: server.get_welcome_text(),
            permissions: Some(root_perm.into()),
        }.into()));
    }

    // 6. ServerConfig
    {
        push_burst(Message::ServerConfig(ServerConfig {
            max_bandwidth: None,
            welcome_text: None,
            allow_html: Some(server.get_allow_html()),
            message_length: Some(server.get_max_text_message_length()),
            image_message_length: Some(server.get_max_image_message_length()),
            max_users: Some(server.get_max_users() as u32),
        }.into()));
    }

    // 7. CodecVersion — advertise Opus-only (OCB2-AES128 encrypted voice)
    {
        push_burst(Message::CodecVersion(CodecVersion {
            alpha: -2147483637, // CELT alpha version (unused, but required by clients)
            beta: 0,
            prefer_alpha: false,
            opus: Some(true),
        }.into()));
    }

    // ── Send the burst to the joining client in one shot ──────────────────
    sender.write_proto_message_batch(&burst).await?;

    // ── Mark as authenticated ─────────────────────────────────────────────
    sender.set_authenticated(true).await;

    // ── Record last-seen versions so the client doesn't replay old entries ─
    sender.update_last_client_versions(&all_versions).await;

    // Store Opus support flag for codec negotiation
    {
        let mut local = sender.write_local_state().await;
        if let Some(ref mut state) = *local {
            state.set_supports_opus(msg.opus.unwrap_or(false));
        }
    }

    // The AddClient log entry (emitted by allocate_local_client) will drive
    // the UserState broadcast to all existing per-client subscribers.
    // No need to broadcast manually here.

    Ok(())
}
