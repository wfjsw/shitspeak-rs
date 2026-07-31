//! A scriptable [`Authenticator`] for tests.
//!
//! Tests register users up front (with optional password and group list), then
//! the [`AuthenticatorAdapter`] satisfies the trait bound on `Server::new` while
//! delegating to the shared `Arc<TestAuthenticator>`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::localization::Language;
use crate::protocol_version::ProtocolVersion;
use shitspeak_auth::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
};

#[derive(Debug, Clone)]
struct ScriptedUser {
    password: Option<String>,
    user_id: Option<u32>,
    groups: Vec<String>,
    is_superuser: bool,
    language: Language,
    virtual_server_id: Option<String>,
    max_bandwidth: Option<u32>,
}

#[derive(Default)]
pub struct TestAuthenticator {
    users: Mutex<HashMap<String, ScriptedUser>>,
    auxiliary_data: Mutex<Vec<TestAuthenticateAuxiliaryData>>,
    authenticate_calls: Mutex<HashMap<String, usize>>,
}

#[derive(Debug, Clone)]
pub struct TestAuthenticateAuxiliaryData {
    ip_address: IpAddr,
    tls_ja4: Option<String>,
    uses_proxy_protocol: bool,
    version: Option<ProtocolVersion>,
    client_name: Option<String>,
    os_name: Option<String>,
    os_version: Option<String>,
}

impl TestAuthenticateAuxiliaryData {
    pub fn ip_address(&self) -> IpAddr {
        self.ip_address
    }

    pub fn tls_ja4(&self) -> Option<&str> {
        self.tls_ja4.as_deref()
    }

    pub fn uses_proxy_protocol(&self) -> bool {
        self.uses_proxy_protocol
    }

    pub fn version(&self) -> Option<ProtocolVersion> {
        self.version
    }

    pub fn client_name(&self) -> Option<&str> {
        self.client_name.as_deref()
    }

    pub fn os_name(&self) -> Option<&str> {
        self.os_name.as_deref()
    }

    pub fn os_version(&self) -> Option<&str> {
        self.os_version.as_deref()
    }
}

impl TestAuthenticator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn authenticated_auxiliary_data(&self) -> Vec<TestAuthenticateAuxiliaryData> {
        self.auxiliary_data.lock().unwrap().clone()
    }

    pub fn authenticate_call_count(&self, username: &str) -> usize {
        self.authenticate_calls
            .lock()
            .unwrap()
            .get(username)
            .copied()
            .unwrap_or(0)
    }

    /// Register (or overwrite) a user. `password = None` means the user logs in
    /// without a password.
    pub fn register_user(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
    ) {
        self.register_user_with_language(name, password, user_id, groups, Language::default());
    }

    pub fn register_superuser(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
    ) {
        self.register_user_with_options(
            name,
            password,
            user_id,
            groups,
            true,
            Language::default(),
            None,
            None,
        );
    }

    pub fn register_user_with_max_bandwidth(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
        max_bandwidth: Option<u32>,
    ) {
        self.register_user_with_options(
            name,
            password,
            user_id,
            groups,
            false,
            Language::default(),
            None,
            max_bandwidth,
        );
    }

    pub fn register_user_with_language(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
        language: Language,
    ) {
        self.register_user_in_server(name, password, user_id, groups, language, None);
    }

    pub fn register_user_in_server(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
        language: Language,
        virtual_server_id: Option<&str>,
    ) {
        self.register_user_with_options(
            name,
            password,
            user_id,
            groups,
            false,
            language,
            virtual_server_id,
            None,
        );
    }

    fn register_user_with_options(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
        is_superuser: bool,
        language: Language,
        virtual_server_id: Option<&str>,
        max_bandwidth: Option<u32>,
    ) {
        self.users.lock().unwrap().insert(
            name.to_owned(),
            ScriptedUser {
                password: password.map(str::to_owned),
                user_id,
                groups,
                is_superuser,
                language,
                virtual_server_id: virtual_server_id.map(str::to_owned),
                max_bandwidth,
            },
        );
    }
}

/// Wraps `Arc<TestAuthenticator>` so it can satisfy the `Authenticator: 'static`
/// bound on `Server::new` while letting tests still mutate the shared registry.
pub struct AuthenticatorAdapter(pub std::sync::Arc<TestAuthenticator>);

#[async_trait]
impl Authenticator for AuthenticatorAdapter {
    async fn authenticate(
        &self,
        username: &str,
        password: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        *self
            .0
            .authenticate_calls
            .lock()
            .unwrap()
            .entry(username.to_owned())
            .or_insert(0) += 1;
        self.0
            .auxiliary_data
            .lock()
            .unwrap()
            .push(TestAuthenticateAuxiliaryData {
                ip_address: auxiliary_data.ip_address,
                tls_ja4: auxiliary_data.tls_ja4.clone(),
                uses_proxy_protocol: auxiliary_data.uses_proxy_protocol,
                version: auxiliary_data.version,
                client_name: auxiliary_data.client_name.clone(),
                os_name: auxiliary_data.os_name.clone(),
                os_version: auxiliary_data.os_version.clone(),
            });
        let entry = {
            let users = self.0.users.lock().unwrap();
            users.get(username).cloned()
        };
        let Some(entry) = entry else {
            return Err(AuthenticationRejection::NoSuchUser);
        };
        if let Some(expected) = entry.password.as_deref() {
            if password != Some(expected) {
                return Err(AuthenticationRejection::WrongPassword);
            }
        }
        Ok(AuthenticateResult {
            auth_session_id: None,
            authenticated_until: None,
            authentication_expiry_action: Default::default(),
            user_id: entry.user_id,
            fqdn: None,
            display_name: Some(username.to_owned()),
            groups: entry.groups,
            is_superuser: entry.is_superuser,
            virtual_server_id: entry.virtual_server_id,
            language: entry.language,
            max_bandwidth: entry.max_bandwidth,
            texture_url: None,
            comment_url: None,
        })
    }
}
