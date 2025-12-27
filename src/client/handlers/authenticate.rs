use std::sync::Arc;

use crate::{client::Client, mumble_proto::Authenticate, server::Server};

pub async fn handle_authenticate(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, msg: Authenticate)  {
    // Handle the authentication logic here

    

    sender.set_tokens(msg.tokens.into_iter().collect()).await;
}
