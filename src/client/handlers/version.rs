use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, messages::encoder::Version, server::Server
};

pub async fn handle_version(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: Version,
) -> Result<(), MessageHandlerError> {
    tracing::debug!(session = u32::from(sender.get_session_id()), version = ?msg.version, release = msg.release, os = msg.os, "Version handler");
    {
        let repo = server.get_clients();
        let mut global_state_writer = sender.write_global_state(repo);
        global_state_writer.set_protocol_version(msg.version);
    }
    {
        let mut local_state_writer = sender.write_local_state();
        if let Some(ref mut state) = *local_state_writer {
            state.set_release(msg.release);
            state.set_os(msg.os);
            state.set_os_version(msg.os_version);
        }
    }

    // Store Opus support flag from the authenticate message (set during auth).
    // The Version message itself doesn't carry codec info — that's in Authenticate.
    // We track it here as a no-op; the actual flag is set in handle_authenticate.

    Ok(())
}
