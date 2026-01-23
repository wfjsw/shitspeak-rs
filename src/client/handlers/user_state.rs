use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, messages::encoder::UserState, server::Server
};

pub async fn handle_user_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserState,
) -> Result<(), MessageHandlerError> {
    // let target = match msg.session {
    //     Some(session) => server.get_clients().get_client(session).await.ok_or("Client not found in server's client map")?,
    //     None => sender.clone(),
    // };

    // let mut broadcast_message = UserState::default();
    // broadcast_message.session = Some(target.get_session_id());
    // broadcast_message.actor = Some(sender.get_session_id());



    // let mut should_broadcast = false;
    
    Ok(())
}
