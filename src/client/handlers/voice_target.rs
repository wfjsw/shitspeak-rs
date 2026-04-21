use std::sync::Arc;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    mumble_proto::VoiceTarget as ProtoVoiceTarget,
    server::Server,
};

pub async fn handle_voice_target(
    _server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: ProtoVoiceTarget,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated().await {
        return Ok(());
    }

    let target_id = msg.id.unwrap_or(0);
    // Valid target IDs are 1..30
    if target_id == 0 || target_id > 30 {
        return Ok(());
    }

    let mut udp_state = sender.udp_state().await;
    let target = udp_state.voice_target_mut(target_id);

    // Clear existing target and rebuild from message
    target.clear();

    for t in &msg.targets {
        for session in &t.session {
            target.add_session(*session);
        }
        if let Some(channel_id) = t.channel_id {
            target.add_channel(crate::client::voice_target::VoiceTargetChannel::new(
                channel_id,
                t.children.unwrap_or(false),
                t.links.unwrap_or(false),
                t.group.clone().unwrap_or_default(),
            ));
        }
    }

    Ok(())
}
