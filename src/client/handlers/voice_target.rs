use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, messages::encoder::VoiceTarget, server::Server,
};

pub async fn handle_voice_target(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: VoiceTarget,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        return Err(MessageHandlerError::protocol_violation(
            "VoiceTarget message received before authentication",
        ));
    }

    let target_id = msg.id.unwrap_or(0);
    tracing::debug!(
        session = u32::from(sender.get_session_id()),
        target_id,
        num_targets = msg.targets.len(),
        "VoiceTarget handler"
    );
    if target_id == 0 || target_id > 30 {
        return Ok(());
    }

    let server_id = sender.server_id();
    let mut valid_sessions = Vec::new();
    let mut valid_channels = Vec::new();

    for t in &msg.targets {
        for session in &t.session {
            let session_id =
                crate::client::client_session_identifier::ClientSessionIdentifier::from(*session);
            if let Some(target) = server
                .get_clients()
                .get_client_in_server(&server_id, session_id)
                .await
            {
                if crate::client::visibility::can_view_user(server, sender, &target).await {
                    valid_sessions.push(*session);
                }
            }
        }
        if let Some(channel_id) = t.channel_id {
            if server
                .get_channels()
                .get_channel_in_server(&server_id, channel_id)
                .await
                .is_some()
            {
                valid_channels.push(crate::client::voice_target::VoiceTargetChannel::new(
                    channel_id,
                    t.children.unwrap_or(false),
                    t.links.unwrap_or(false),
                    t.group.clone().unwrap_or_default(),
                ));
            }
        }
    }

    let mut target = crate::client::voice_target::VoiceTarget::new();
    for session in valid_sessions {
        target.add_session(session);
    }
    for channel in valid_channels {
        target.add_channel(channel);
    }
    sender.set_voice_target(target_id, target);

    Ok(())
}
