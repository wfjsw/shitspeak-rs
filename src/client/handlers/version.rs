use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, messages::encoder::Version, server::Server
};

pub async fn handle_version(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: Version,
) -> Result<(), MessageHandlerError> {
    {
        let mut global_state_writer = sender.write_global_state().await;
        global_state_writer.set_protocol_version(msg.version);
        global_state_writer.set_release(msg.release);
        global_state_writer.set_os(msg.os);
        global_state_writer.set_os_version(msg.os_version);

        // TODO: set crypto mode
        // sender.crypt_state().await.as_mut().map(|state| {
        //     state.set_protocol_version(msg.version);
        //     state.set_release(msg.release.clone());
        //     state.set_os(msg.os.clone());
        //     state.set_os_version(msg.os_version.clone());
        // });
    }
    
    Ok(())
}
