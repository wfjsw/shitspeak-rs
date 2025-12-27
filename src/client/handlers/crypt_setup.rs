use std::sync::Arc;

use crate::{client::Client, mumble_proto::CryptSetup, server::Server};

pub fn handle_crypt_setup(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, msg: CryptSetup) {
    // Handle crypt setup message logic here
}

