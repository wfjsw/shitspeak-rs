use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, messages::encoder::UserState, server::Server
};

pub async fn handle_user_state(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: UserState,
) -> Result<(), MessageHandlerError> {
    // Handle channel remove message logic here
    Ok(())
}
