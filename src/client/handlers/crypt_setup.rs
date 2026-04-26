use std::sync::Arc;

use bytes::Bytes;

use crate::{
    client::Client,
    errors::MessageHandlerError,
    messages::{encoder::{CryptSetup, RejectType}, Message, WriteMessageExt},
    server::Server,
};

pub async fn handle_crypt_setup(
    _server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: CryptSetup,
) -> Result<(), MessageHandlerError> {
    let session = sender.get_session_id();
    tracing::debug!(session = u32::from(session), is_resync = msg.is_client_request_resync(), has_client_nonce = msg.client_nonce().is_some(), "CryptSetup handler");

    // A CryptSetup message from the client has two meanings:
    //
    //  1. client_nonce present  → client is requesting a decrypt IV resync
    //     (e.g. after a packet loss burst).  Adopt the client's nonce as the
    //     new decrypt IV.
    //
    //  2. client_nonce absent   → client wants a full key re-exchange.
    //     Regenerate the whole crypt state and send the new key back.

    if msg.is_client_request_resync() {
        // Full re-key
        sender
            .create_crypt_state("OCB2-AES128")
            .await
            .map_err(|_| RejectType::AuthenticatorFail)?;

        let reply: Message = {
            let crypt = sender.crypt_state().await;
            let state = crypt.as_ref().expect("crypt state just created");
            CryptSetup::new(
                state.key().map(Bytes::copy_from_slice),
                Some(Bytes::copy_from_slice(state.encrypt_iv())),
                Some(Bytes::copy_from_slice(state.decrypt_iv())),
            ).into()
        };

        sender.write_proto_message(&reply).await?;
    } else if let Some(client_nonce) = msg.client_nonce().map(|n| n.to_vec()) {
        // Decrypt IV resync — adopt the client's nonce
        let reply: Message = {
            let mut crypt = sender.crypt_state().await;
            if let Some(state) = crypt.as_mut() {
                state.set_decrypt_iv(&client_nonce);
            }

            // Acknowledge: send our current encrypt IV as server_nonce
            let encrypt_iv = crypt
                .as_ref()
                .map(|s| s.encrypt_iv().to_vec())
                .unwrap_or_default();
            CryptSetup::new(
                None,
                None,
                Some(Bytes::from(encrypt_iv)),
            ).into()
        };
        // Drop the crypt lock before the async write
        sender.write_proto_message(&reply).await?;
    }

    Ok(())
}
