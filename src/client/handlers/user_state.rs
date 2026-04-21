use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, WriteMessageExt, encoder::UserState},
    mumble_proto::{
        PermissionDenied,
        permission_denied::DenyType,
    },
    server::Server,
};

pub async fn handle_user_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserState,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let sender_id = sender.get_session_id();

    // Determine whether this is a self-update or a moderator action.
    let target = match msg.session {
        Some(session_id) if session_id != sender_id => {
            // Acting on another user — TODO: check MuteDeafen / Move permissions.
            match server.get_clients().get_client(session_id).await {
                Some(c) => c,
                None => return Ok(()), // target gone, ignore
            }
        }
        _ => sender.clone(),
    };

    let target_id = target.get_session_id();
    let is_self = target_id == sender_id;

    // Build the broadcast delta — only fields that actually changed.
    let mut delta = UserState::default();
    delta.session = Some(target_id);
    delta.actor = Some(sender_id);

    let mut changed = false;

    // ── Self-mute / self-deaf (only target can set their own) ─────────────
    if is_self {
        if let Some(self_mute) = msg.self_mute {
            let mut gs = target.write_global_state().await;
            if gs.is_self_muted() != self_mute {
                gs.set_self_mute(self_mute);
                // Implicitly clear self-deaf when unmuting
                if !self_mute {
                    gs.set_self_deaf(false);
                    delta.self_deaf = Some(false);
                }
                delta.self_mute = Some(self_mute);
                changed = true;
            }
        }
        if let Some(self_deaf) = msg.self_deaf {
            let mut gs = target.write_global_state().await;
            if gs.is_self_deafened() != self_deaf {
                gs.set_self_deaf(self_deaf);
                // Implicitly self-mute when self-deafening
                if self_deaf && !gs.is_self_muted() {
                    gs.set_self_mute(true);
                    delta.self_mute = Some(true);
                }
                delta.self_deaf = Some(self_deaf);
                changed = true;
            }
        }
    }

    // ── Moderator: server mute/deaf/suppress ─────────────────────────────
    if !is_self {
        if let Some(mute) = msg.mute {
            let mut gs = target.write_global_state().await;
            if gs.is_muted() != mute {
                gs.set_mute(mute);
                delta.mute = Some(mute);
                changed = true;
            }
        }
        if let Some(deaf) = msg.deaf {
            let mut gs = target.write_global_state().await;
            if gs.is_deafened() != deaf {
                gs.set_deaf(deaf);
                delta.deaf = Some(deaf);
                changed = true;
            }
        }
        if let Some(suppress) = msg.suppress {
            let mut gs = target.write_global_state().await;
            if gs.is_suppressed() != suppress {
                gs.set_suppress(suppress);
                delta.suppress = Some(suppress);
                changed = true;
            }
        }
        if let Some(priority_speaker) = msg.priority_speaker {
            let mut gs = target.write_global_state().await;
            if gs.is_priority_speaker() != priority_speaker {
                gs.set_priority_speaker(priority_speaker);
                delta.priority_speaker = Some(priority_speaker);
                changed = true;
            }
        }
    }

    // ── Recording (self only) ─────────────────────────────────────────────
    if is_self {
        if let Some(recording) = msg.recording {
            let mut gs = target.write_global_state().await;
            if gs.is_recording() != recording {
                gs.set_recording(recording);
                delta.recording = Some(recording);
                changed = true;
            }
        }
    }

    // ── Channel move ──────────────────────────────────────────────────────
    if let Some(new_channel_id) = msg.channel_id {
        let current = target.get_current_channel_id().await;
        if current != new_channel_id {
            // Verify the channel exists
            if server.get_channels().get_channel(new_channel_id).await.is_none() {
                let deny = Message::PermissionDenied(PermissionDenied {
                    r#type: Some(DenyType::MissingCertificate as i32), // generic "invalid" — TODO proper type
                    session: Some(u32::from(sender_id)),
                    channel_id: Some(new_channel_id),
                    reason: Some(format!("Channel {} does not exist", new_channel_id)),
                    name: None,
                    permission: None,
                });
                sender.write_proto_message(&deny).await?;
                return Ok(());
            }
            target.set_current_channel_id(new_channel_id).await;
            delta.channel_id = Some(new_channel_id);
            changed = true;
        }
    }

    // ── Listening channel add/remove ──────────────────────────────────────
    if !msg.listening_channel_add.is_empty() || !msg.listening_channel_remove.is_empty() {
        let mut gs = target.write_global_state().await;
        let mut adds = Vec::new();
        let mut removes = Vec::new();
        for ch in &msg.listening_channel_add {
            if gs.listen_channel(*ch) {
                adds.push(*ch);
            }
        }
        for ch in &msg.listening_channel_remove {
            if gs.unlisten_channel(*ch) {
                removes.push(*ch);
            }
        }
        if !adds.is_empty() || !removes.is_empty() {
            delta.listening_channel_add = adds;
            delta.listening_channel_remove = removes;
            changed = true;
        }
    }

    // ── Comment update ────────────────────────────────────────────────────
    if let Some(comment) = msg.comment {
        // Store inline if small; store as blob (hash-only) if large.
        // For now, store small comments inline and clear blob hash.
        let is_small = comment.len() <= 128;
        {
            let mut gs = target.write_global_state().await;
            if is_small {
                gs.clear_comment_blob();
            } else {
                // TODO: push to blob store, set hash
                gs.clear_comment_blob();
            }
        }
        if is_small {
            delta.comment = Some(comment);
        }
        // For target, send back hash
        delta.comment_hash = None;
        changed = true;
    }

    // ── Texture update ────────────────────────────────────────────────────
    if let Some(texture) = msg.texture {
        let is_small = texture.len() <= 128;
        {
            let mut gs = target.write_global_state().await;
            if is_small {
                gs.clear_texture_blob();
            } else {
                gs.clear_texture_blob();
            }
        }
        if is_small {
            delta.texture = Some(texture);
        }
        changed = true;
    }

    // ── Plugin context/identity (self only, not broadcast to others) ──────
    if is_self {
        let mut ctx_changed = false;
        if let Some(ctx) = msg.plugin_context {
            let mut gs = target.write_global_state().await;
            gs.set_plugin_context(ctx);
            ctx_changed = true;
        }
        if let Some(identity) = msg.plugin_identity {
            let mut gs = target.write_global_state().await;
            gs.set_plugin_identity(identity);
            ctx_changed = true;
        }
        // Plugin context changes are NOT broadcast — just ACK to sender
        if ctx_changed {
            let _ = ctx_changed; // handled below via changed flag omission
        }
    }

    if !changed {
        return Ok(());
    }

    // ── Broadcast delta to all clients ────────────────────────────────────
    let msg_out: Message = delta.into();
    server.get_clients().broadcast_all(&msg_out).await;

    Ok(())
}
