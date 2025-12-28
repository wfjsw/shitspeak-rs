use std::sync::Arc;

use crate::{client::Client, errors::MessageHandlerError, mumble_proto::Authenticate, server::Server};

pub async fn handle_authenticate(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, msg: Authenticate)  -> Result<(), MessageHandlerError> {
    // Handle the authentication logic here

    if sender.is_authenticated().await {
        
    }

    sender.set_tokens(msg.tokens.into_iter().collect()).await;
    Ok(())
}
