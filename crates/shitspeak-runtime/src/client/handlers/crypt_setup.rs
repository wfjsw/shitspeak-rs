use std::sync::Arc;

use bytes::Bytes;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{Message, encoder::CryptSetup},
    server::Server,
};

pub async fn handle_crypt_setup(
    _server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: CryptSetup,
) -> Result<(), MessageHandlerError> {
    let session = sender.get_session_id();
    tracing::debug!(
        session = u32::from(session),
        is_resync = msg.is_client_request_resync(),
        has_client_nonce = msg.client_nonce().is_some(),
        "CryptSetup handler"
    );

    if msg.is_client_request_resync() {
        // An empty request asks for the server's current outbound nonce. Keep
        // the existing key and client nonce.
        let reply: Message = {
            let crypt = sender.crypt_state();
            let server_nonce = crypt
                .as_ref()
                .map(|state| Bytes::copy_from_slice(state.encrypt_iv()));
            CryptSetup::new(None, None, server_nonce).into()
        };

        sender.write_proto_message(&reply).await?;
    } else if let Some(client_nonce) = msg.client_nonce().map(|n| n.to_vec()) {
        // A supplied client nonce replaces the server's inbound nonce. Murmur
        // does not send an acknowledgement for this form.
        let mut crypt = sender.crypt_state();
        if let Some(state) = crypt.as_mut() {
            if client_nonce.len() == state.decrypt_iv().len() {
                state.set_decrypt_iv(&client_nonce);
            } else {
                tracing::warn!(
                    session = u32::from(session),
                    nonce_len = client_nonce.len(),
                    "ignoring invalid client crypto nonce"
                );
            }
        }
    }

    Ok(())
}
