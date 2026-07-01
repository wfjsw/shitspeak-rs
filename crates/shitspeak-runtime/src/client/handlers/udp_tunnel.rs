use std::sync::Arc;

use bytes::Bytes;

use crate::{errors::MessageHandlerError, server::Server};

pub(super) async fn handle_udp_tunnel(
    _server: &Arc<Box<Server>>,
    sender: &Arc<Box<crate::client::Client>>,
    data: Bytes,
) -> Result<(), MessageHandlerError> {
    if !sender.is_authenticated() {
        tracing::trace!(
            session = u32::from(sender.get_session_id()),
            len = data.len(),
            "dropping UDPTunnel before authentication completed"
        );
        return Ok(());
    }

    // Match Mumble/shitspeak behavior: a tunneled voice packet means
    // this client currently prefers TCP transport for voice.
    sender.set_prefer_tcp_tunnel(true);

    match crate::voice::codec::Audio::decode(&data, Some(sender.get_session_id())) {
        Ok(audio) => {
            crate::voice::metrics::record_ingress(
                crate::voice::metrics::VoiceIngressTransport::TcpTunnel,
                data.len(),
            );
            tracing::trace!(session = u32::from(sender.get_session_id()), target = %audio.target, frame = audio.frame_number, len = audio.audio_payload.len(), "UDPTunnel: routing voice");
            sender.push_voice_routing(audio);
            Ok(())
        }
        Err(e) => {
            tracing::trace!(session = u32::from(sender.get_session_id()), len = data.len(), error = %e, "UDPTunnel: decode failed");
            return Err(MessageHandlerError::protocol_violation(format!(
                "Failed to decode UDPTunnel audio packet: {e}"
            )));
        }
    }
}
