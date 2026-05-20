use std::collections::HashSet;
use std::sync::Arc;

use crate::{
    acl::ACLPermissions,
    client::Client,
    errors::MessageHandlerError,
    localization::channel_does_not_exist,
    messages::encoder::{DenyType, PermissionDenied},
    server::Server,
};

pub async fn handle_user_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: crate::messages::encoder::UserState,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "UserState message received before authentication",
        ));
    }

    let sender_id = sender.get_session_id();
    let server_id = sender.server_id();
    tracing::debug!(
        session = u32::from(sender_id),
        self_mute = msg.self_mute,
        self_deaf = msg.self_deaf,
        mute = msg.mute,
        deaf = msg.deaf,
        channel_id = msg.channel_id,
        "UserState handler"
    );
    let repo = server.get_clients();
    let local_node_id = repo.local_node_id();

    // Determine whether this is a self-update or a moderator action
    // against a known local or replicated target.
    let target = match msg.session {
        Some(session_id) if session_id != sender_id => {
            match repo.get_client_in_server(&server_id, session_id).await {
                Some(c) => c,
                None => return Ok(()), // target gone, ignore
            }
        }
        _ => sender.clone(),
    };

    let target_id = target.get_session_id();
    let is_self = target_id == sender_id;
    let target_current_channel_id = target.get_current_channel_id();
    let requested_channel_change = msg
        .channel_id
        .filter(|new_channel_id| *new_channel_id != target_current_channel_id);

    let mut actor_source_perms = None;
    let mut target_destination_perms = None;

    // ── ACL: Channel move ────────────────────────────────────────────────
    // Check permissions before acquiring the guard, so we can return early.
    let requested_channel_change = if let Some(new_channel_id) = requested_channel_change {
        let redirected = if server
            .get_channels()
            .get_channel_in_server(&server_id, new_channel_id)
            .await
            .is_some()
        {
            server
                .get_channels()
                .redirect_pending_delete_target_in_server(&server_id, new_channel_id)
                .await
        } else {
            new_channel_id
        };
        Some(redirected).filter(|redirected| *redirected != target_current_channel_id)
    } else {
        None
    };

    if let Some(new_channel_id) = requested_channel_change {
        let dst_chan = server
            .get_channels()
            .get_channel_in_server(&server_id, new_channel_id)
            .await;
        if dst_chan
            .as_ref()
            .is_some_and(|channel| channel.is_temporary())
            && !is_self
        {
            return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                r#type: DenyType::TemporaryChannel,
                session: u32::from(sender_id),
                channel_id: Some(new_channel_id),
                reason: None,
                name: None,
                permission: None,
            }));
        }
        if dst_chan.is_none() {
            return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                r#type: DenyType::ChannelName,
                session: u32::from(sender_id),
                channel_id: Some(new_channel_id),
                reason: Some(channel_does_not_exist(sender.language(), new_channel_id)),
                name: None,
                permission: None,
            }));
        }

        let dst_perms =
            crate::client::acl::compute_permissions_for_client(server, &target, new_channel_id)
                .await;
        target_destination_perms = Some(dst_perms);

        if is_self {
            // Moving self: need Enter on destination.
            if !dst_perms.contains(ACLPermissions::Enter) {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(target_id),
                        Some(new_channel_id),
                        ACLPermissions::Enter,
                    ),
                ));
            }
        } else {
            // Moving others: need Move on target's current channel.
            let src_perms = crate::client::acl::compute_permissions_for_client(
                server,
                sender,
                target_current_channel_id,
            )
            .await;
            actor_source_perms = Some(src_perms);
            if !src_perms.contains(ACLPermissions::Move) {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(sender_id),
                        Some(target_current_channel_id),
                        ACLPermissions::Move,
                    ),
                ));
            }

            // If target lacks Enter on destination, actor needs Move on destination too.
            if !dst_perms.contains(ACLPermissions::Enter) {
                let actor_dst = crate::client::acl::compute_permissions_for_client(
                    server,
                    sender,
                    new_channel_id,
                )
                .await;
                if !actor_dst.contains(ACLPermissions::Move) {
                    return Err(MessageHandlerError::PermissionDenied(
                        PermissionDenied::for_permission(
                            u32::from(sender_id),
                            Some(new_channel_id),
                            ACLPermissions::Move,
                        ),
                    ));
                }
            }

            if !src_perms.contains(ACLPermissions::Traverse) {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(sender_id),
                        Some(target_current_channel_id),
                        ACLPermissions::Traverse,
                    ),
                ));
            }

            if !dst_perms.contains(ACLPermissions::Traverse) {
                return Err(MessageHandlerError::PermissionDenied(
                    PermissionDenied::for_permission(
                        u32::from(target_id),
                        Some(new_channel_id),
                        ACLPermissions::Traverse,
                    ),
                ));
            }
        }
    }

    if msg.suppress.is_some() {
        return Err(MessageHandlerError::PermissionDenied(
            PermissionDenied::for_permission(
                u32::from(sender_id),
                Some(target_current_channel_id),
                ACLPermissions::MuteDeafen,
            ),
        ));
    }

    // ── ACL: Mute/deaf/priority_speaker (moderator actions) ──────
    if (msg.mute.is_some() || msg.deaf.is_some() || msg.priority_speaker.is_some())
        && (!is_self || msg.priority_speaker.is_some())
    {
        let perms = match actor_source_perms {
            Some(perms) => perms,
            None => {
                crate::client::acl::compute_permissions_for_client(
                    server,
                    sender,
                    target_current_channel_id,
                )
                .await
            }
        };
        if !perms.contains(ACLPermissions::MuteDeafen) {
            return Err(MessageHandlerError::PermissionDenied(
                PermissionDenied::for_permission(
                    u32::from(sender_id),
                    Some(target_current_channel_id),
                    ACLPermissions::MuteDeafen,
                ),
            ));
        }
    }

    if !is_self
        && (!msg.listening_channel_add.is_empty() || !msg.listening_channel_remove.is_empty())
    {
        return Err(MessageHandlerError::protocol_violation(
            "non-self UserState contains self-only listening channel fields",
        ));
    }

    // ── ACL: Listening channel add ────────────────────────────────────────
    let mut checked_listen_channels = HashSet::new();
    for ch_id in &msg.listening_channel_add {
        if !checked_listen_channels.insert(*ch_id) {
            continue;
        }
        let perms =
            crate::client::acl::compute_permissions_for_client(server, sender, *ch_id).await;
        if !perms.contains(ACLPermissions::Listen) {
            return Err(MessageHandlerError::PermissionDenied(
                PermissionDenied::for_permission(
                    u32::from(sender_id),
                    Some(*ch_id),
                    ACLPermissions::Listen,
                ),
            ));
        }
    }

    if !is_self
        && (msg.self_mute.is_some()
            || msg.self_deaf.is_some()
            || msg.plugin_context.is_some()
            || msg.plugin_identity.is_some()
            || msg.recording.is_some()
            || msg.temporary_access_tokens.len() > 0
            || msg.listening_volume_adjustment.len() > 0)
    {
        return Err(MessageHandlerError::protocol_violation(
            "non-self UserState contains self-only fields",
        ));
    }

    if !is_self && (msg.comment.is_some() || msg.texture.is_some()) {
        let root_perms =
            crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
        if !root_perms.contains(ACLPermissions::ResetUserContent) {
            return Err(MessageHandlerError::PermissionDenied(
                PermissionDenied::for_permission(
                    u32::from(sender_id),
                    Some(0),
                    ACLPermissions::ResetUserContent,
                ),
            ));
        }

        if msg
            .comment
            .as_deref()
            .is_some_and(|comment| !comment.is_empty())
            || msg
                .texture
                .as_ref()
                .is_some_and(|texture| !texture.is_empty())
        {
            return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                r#type: DenyType::TextTooLong,
                session: u32::from(sender_id),
                channel_id: None,
                reason: None,
                name: None,
                permission: None,
            }));
        }
    }

    let comment_blob_hash = match msg.comment.as_ref() {
        Some(comment) if comment.is_empty() => {
            if let Some(user_id) = target.get_user_id() {
                if server
                    .get_authenticator()
                    .set_user_comment(user_id, String::new())
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        user_id,
                        session = u32::from(target_id),
                        "authenticator rejected comment blob clear"
                    );
                }
            }
            Some(None)
        }
        Some(comment) => {
            let max_len = server.get_max_text_message_length() as usize;
            if max_len > 0 && comment.len() > max_len {
                return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                    r#type: DenyType::TextTooLong,
                    session: u32::from(sender_id),
                    channel_id: None,
                    reason: None,
                    name: None,
                    permission: None,
                }));
            }
            let hash = server
                .get_session_blobs()
                .put_content(comment.as_bytes())
                .await
                .map_err(|e| {
                    tracing::warn!(
                        error = %e,
                        session = u32::from(target_id),
                        "failed to store comment blob"
                    );
                    MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::Text,
                        session: u32::from(sender_id),
                        channel_id: None,
                        reason: Some(format!("Failed to store comment blob: {e}").into()),
                        name: None,
                        permission: None,
                    })
                })?;
            if let Some(user_id) = target.get_user_id() {
                if server
                    .get_authenticator()
                    .set_user_comment(user_id, comment.clone())
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        user_id,
                        session = u32::from(target_id),
                        "authenticator rejected comment blob update"
                    );
                }
            }
            Some(Some(hash))
        }
        None => None,
    };

    let texture_blob_hash = match msg.texture.as_ref() {
        Some(texture) if texture.is_empty() => {
            if let Some(user_id) = target.get_user_id() {
                if server
                    .get_authenticator()
                    .set_user_texture(user_id, bytes::Bytes::new())
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        user_id,
                        session = u32::from(target_id),
                        "authenticator rejected texture blob clear"
                    );
                }
            }
            Some(None)
        }
        Some(texture) => {
            let max_len = server.get_max_image_message_length() as usize;
            if max_len > 0 && texture.len() > max_len {
                return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                    r#type: DenyType::TextTooLong,
                    session: u32::from(sender_id),
                    channel_id: None,
                    reason: None,
                    name: None,
                    permission: None,
                }));
            }
            let hash = server
                .get_session_blobs()
                .put_content(texture)
                .await
                .map_err(|e| {
                    tracing::warn!(
                        error = %e,
                        session = u32::from(target_id),
                        "failed to store texture blob"
                    );
                    MessageHandlerError::PermissionDenied(PermissionDenied {
                        r#type: DenyType::Text,
                        session: u32::from(sender_id),
                        channel_id: None,
                        reason: Some(format!("Failed to store texture blob: {e}").into()),
                        name: None,
                        permission: None,
                    })
                })?;
            if let Some(user_id) = target.get_user_id() {
                if server
                    .get_authenticator()
                    .set_user_texture(user_id, texture.clone())
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        user_id,
                        session = u32::from(target_id),
                        "authenticator rejected texture blob update"
                    );
                }
            }
            Some(Some(hash))
        }
        None => None,
    };

    if let Some(target_session_id) = msg.session {
        if target_session_id != sender_id && target_session_id.get_node_id() != local_node_id {
            if let Some(app) = server.s2s_manager().application() {
                let patch = crate::s2s::application::proto::UserStatePatch {
                    channel_id: requested_channel_change,
                    mute: msg.mute,
                    deaf: msg.deaf,
                    suppress: requested_channel_change.and_then(|_| {
                        target_destination_perms.map(|perms| !perms.contains(ACLPermissions::Speak))
                    }),
                    priority_speaker: msg.priority_speaker,
                    listening_channel_add: msg.listening_channel_add.clone(),
                    listening_channel_remove: msg.listening_channel_remove.clone(),
                    expected_from_channel: Some(target_current_channel_id),
                };
                if let Err(e) = app
                    .moderation()
                    .dispatch_user_state_in_server(&server_id, sender_id, target_session_id, patch)
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        target = u32::from(target_session_id),
                        "moderation dispatch_user_state failed",
                    );
                }
            } else {
                tracing::trace!(
                    target = u32::from(target_session_id),
                    "cross-owner UserState dropped: ApplicationLayer not attached",
                );
            }
            return Ok(());
        }
    }

    // ── Acquire a single transactional guard for all mutations ─────────
    // All changes in this handler are batched into one version bump.
    // Channel-dependent operations (move, mute/deaf by moderator) need the
    // current channel version as a causal dependency.
    let channel_version_dep = if requested_channel_change.is_some() || !is_self {
        Some(server.get_channels().current_version_in_server(&server_id))
    } else {
        None
    };
    let mut gs = target.write_global_state_as(repo, Some(sender_id), channel_version_dep);

    // ── Self-mute / self-deaf (only target can set their own) ─────────────
    if is_self {
        if let Some(self_mute) = msg.self_mute {
            if gs.is_self_muted() != self_mute {
                gs.set_self_mute(self_mute);
                // Implicitly clear self-deaf when unmuting
                if !self_mute {
                    gs.set_self_deaf(false);
                }
            }
        }
        if let Some(self_deaf) = msg.self_deaf {
            if gs.is_self_deafened() != self_deaf {
                gs.set_self_deaf(self_deaf);
                // Implicitly self-mute when self-deafening
                if self_deaf && !gs.is_self_muted() {
                    gs.set_self_mute(true);
                }
            }
        }
    }

    // ── Moderator: server mute/deaf/suppress ─────────────────────────────
    if !is_self {
        if let Some(mute) = msg.mute {
            if gs.is_muted() != mute {
                gs.set_mute(mute);
                // Implicitly clear deaf when unmuting
                if !mute {
                    gs.set_deaf(false);
                }
            }

            if gs.is_suppressed() && !mute {
                gs.set_suppress(false);
            }
        }
        if let Some(deaf) = msg.deaf {
            if gs.is_deafened() != deaf {
                gs.set_deaf(deaf);
                // Implicitly mute when deafening
                if deaf && !gs.is_muted() {
                    gs.set_mute(true);
                }
            }
        }
    }

    if !is_self {
        if let Some(priority_speaker) = msg.priority_speaker {
            if gs.is_priority_speaker() != priority_speaker {
                gs.set_priority_speaker(priority_speaker);
            }
        }
    }

    // ── Recording (self only) ─────────────────────────────────────────────
    if is_self {
        if let Some(recording) = msg.recording {
            if gs.is_recording() != recording {
                gs.set_recording(recording);
            }
        }
    }

    // ── Channel move ──────────────────────────────────────────────────────
    if let Some(new_channel_id) = requested_channel_change {
        gs.set_current_channel_id(new_channel_id);

        if let Some(dst_perms) = target_destination_perms {
            gs.set_suppress(!dst_perms.contains(ACLPermissions::Speak));
        }
    }

    // ── Listening channel add/remove ──────────────────────────────────────
    if !msg.listening_channel_add.is_empty() || !msg.listening_channel_remove.is_empty() {
        for ch in &msg.listening_channel_add {
            gs.listen_channel(*ch);
        }
        for ch in &msg.listening_channel_remove {
            gs.unlisten_channel(*ch);
        }
    }

    // ── Comment update ────────────────────────────────────────────────────
    if let Some(comment_blob_hash) = comment_blob_hash {
        match comment_blob_hash {
            Some(hash) => gs.set_comment_blob(None, Some(hash)),
            None => gs.clear_comment_blob(),
        }
    }

    // ── Texture update ────────────────────────────────────────────────────
    if let Some(texture_blob_hash) = texture_blob_hash {
        match texture_blob_hash {
            Some(hash) => gs.set_texture_blob(None, Some(hash)),
            None => gs.clear_texture_blob(),
        }
    }

    // ── Plugin context/identity (self only) ───────────────────────────────
    if is_self {
        if let Some(ctx) = msg.plugin_context {
            gs.set_plugin_context(ctx);
        }
        if let Some(identity) = msg.plugin_identity {
            gs.set_plugin_identity(identity);
        }
    }

    // Guard drops here → auto-commits delta, bumps version, broadcasts via log.
    Ok(())
}
