use std::net::IpAddr;

use async_trait::async_trait;

use crate::protocol_version::ProtocolVersion;

#[derive(Debug)]
pub enum AuthenticationRejection {
    WrongPassword,
    NoSuchUser,
    RetryLater,
}

#[derive(Debug)]
pub struct AuthenticateResult {
    pub user_id: u32,
    pub username: String,
    pub groups: Vec<String>,
}

pub struct AuthenticateAuxiliaryData {
    pub certificate_hash: Option<Vec<u8>>,
    pub session_id: Option<u32>,
    pub ip_address: Option<IpAddr>,
    pub version: Option<ProtocolVersion>,
    pub client_name: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
}

#[async_trait]
pub trait Authenticator: Send + Sync + 'static {
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection>;
}
