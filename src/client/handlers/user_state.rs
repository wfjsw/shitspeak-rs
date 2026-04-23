use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    mumble_proto::{
        PermissionDenied,
        permission_denied::DenyType,
    },
    server::Server,
};

pub async fn handle_user_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: crate::messages::encoder::UserState,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let sender_id = sender.get_session_id();
    tracing::debug!(session = u32::from(sender_id), self_mute = msg.self_mute, self_deaf = msg.self_deaf, mute = msg.mute, deaf = msg.deaf, channel_id = msg.channel_id, "UserState handler");
    let repo = server.get_clients();

    // Determine whether this is a self-update or a moderator action.
    let target = match msg.session {
        Some(session_id) if session_id != sender_id => {
            // Acting on another user — TODO: check MuteDeafen / Move permissions.
            match repo.get_client(session_id).await {
                Some(c) => c,
                None => return Ok(()), // target gone, ignore
            }
        }
        _ => sender.clone(),
    };

    let target_id = target.get_session_id();
    let is_self = target_id == sender_id;

    // ── Acquire a single transactional guard for all mutations ─────────
    // All changes in this handler are batched into one version bump.
    // Channel-dependent operations (move, mute/deaf by moderator) need the
    // current channel version as a causal dependency.
    let channel_version_dep = if msg.channel_id.is_some() || !is_self {
        Some(server.get_channels().current_version())
    } else {
        None
    };
    let mut gs = target.write_global_state_as(repo, Some(sender_id), channel_version_dep).await;

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

        if let Some(suppress) = msg.suppress {
            if gs.is_suppressed() != suppress {
                gs.set_suppress(suppress);
            }
        }
    }


    if let Some(priority_speaker) = msg.priority_speaker {
        if gs.is_priority_speaker() != priority_speaker {
            gs.set_priority_speaker(priority_speaker);
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
    if let Some(new_channel_id) = msg.channel_id {
        let current = gs.get_current_channel_id();
        if current != new_channel_id {
            // Verify the channel exists
            if new_channel_id != 0 && server.get_channels().get_channel(new_channel_id).await.is_none() {
                return Err(MessageHandlerError::PermissionDenied(PermissionDenied {
                    r#type: Some(DenyType::ChannelName as i32),
                    session: Some(u32::from(sender_id)),
                    channel_id: Some(new_channel_id),
                    reason: Some(format!("Channel {} does not exist", new_channel_id)),
                    name: None,
                    permission: None,
                }));
            }
            gs.set_current_channel_id(new_channel_id);
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
    if let Some(_comment) = msg.comment {
        // Store inline if small; store as blob (hash-only) if large.
        // For now, store small comments inline and clear blob hash.
        gs.clear_comment_blob();
        // TODO: push large comments to blob store, set hash
    }

    // ── Texture update ────────────────────────────────────────────────────
    if let Some(_texture) = msg.texture {
        gs.clear_texture_blob();
        // TODO: push large textures to blob store, set hash
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
