use std::sync::Arc;

use crate::{
    api::{AuthenticateAuxiliaryData, AuthenticationRejection},
    client::Client,
    errors::{AuthRejection, MessageHandlerError},
    messages::encoder::Authenticate,
    mumble_proto::reject::RejectType,
    server::Server,
};

pub async fn handle_authenticate(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    msg: Authenticate,
) -> Result<(), MessageHandlerError> {
    // Handle the authentication logic here

    if sender.is_authenticated().await {
        // Set access tokens. Clients can set their access tokens any time
        // by sending an Authenticate message with he contents of their new
        // access token list.
        sender.set_tokens(msg.tokens.into_iter().collect()).await;
        return Ok(());
    }

    // Did we get a username?
    let username = msg.username.ok_or(RejectType::InvalidUsername)?;
    let password = msg.password.unwrap_or_default();

    let certificate_hash = sender.get_certificate_hash().map(|hash| hash.to_vec());
    let session_id = sender.get_session_id();
    let ip_address = sender.get_real_ip_address();
    let (version, client_name, os_name, os_version) = {
        let global_state = sender.read_global_state().await;
        (
            global_state.get_protocol_version(),
            global_state.get_release().map(|s| s.to_owned()),
            global_state.get_os_name().map(|s| s.to_owned()),
            global_state.get_os_version().map(|s| s.to_owned()),
        )
    };

    // authenticate
    let authenticator = server.get_authenticator();
    let auth_result = authenticator
        .authenticate(
            &username,
            &password,
            &AuthenticateAuxiliaryData {
                certificate_hash,
                session_id,
                ip_address,
                version,
                client_name,
                os_name,
                os_version,
            },
        )
        .await;

    let result = match auth_result {
        Ok(result) => result,
        Err(AuthenticationRejection::NoSuchUser) => return Err(RejectType::InvalidUsername.into()),
        Err(AuthenticationRejection::WrongPassword) => return Err(RejectType::WrongUserPw.into()),
        Err(AuthenticationRejection::RetryLater) => {
            return Err(RejectType::AuthenticatorFail.into())
        }
    };


    Ok(())
}
