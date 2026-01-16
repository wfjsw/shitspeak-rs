use std::sync::Arc;

use crate::{
    api::{AuthenticateAuxiliaryData, AuthenticationRejection}, client::Client, errors::{AuthRejection, MessageHandlerError}, messages::encoder::Authenticate, mumble_proto::reject::RejectType, server::Server
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
    // let username = match msg.username {
    //     Some(name) => name,
    //     None => {
    //         return Err(AuthRejection::new(RejectType::InvalidUsername).into());
    //     }
    // };

    let username = msg.username.ok_or( RejectType::InvalidUsername)?;
    let password = msg.password.unwrap_or_default();

    // authenticate
    let authenticator = server.get_authenticator();
    let auth_result = authenticator.authenticate(&username, &password, &AuthenticateAuxiliaryData {
        certificate_hash: sender.get_certificate_hash().map(|hash| hash.to_vec()),
        session_id: Some(sender.get_session_id()),
        ip_address: todo!(),
        version: todo!(),
        client_name: todo!(),
        os_name: todo!(),
        os_version: todo!(),
        
    }).await;

    match auth_result {
        Ok(result) => todo!(),
        Err(AuthenticationRejection::NoSuchUser) => todo!(), // TODO Guest handling
        
        Err(AuthenticationRejection::WrongPassword) => return Err(RejectType::WrongUserPw.into()),
        Err(AuthenticationRejection::RetryLater) => return Err(RejectType::AuthenticatorFail.into()),
    }

    // let password = match 

    Ok(())
}
