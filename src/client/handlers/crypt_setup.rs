use std::sync::Arc;

use crate::{
    client::Client, errors::MessageHandlerError, messages::encoder::CryptSetup, server::Server,
};

pub async fn handle_crypt_setup(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: CryptSetup,
) -> Result<(), MessageHandlerError> {
    // Handle crypt setup message logic here
    Ok(())
}
