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
    Privilege, Privileges,
};

#[derive(Debug, Clone)]
struct ScriptedUser {
    password: Option<String>,
    user_id: Option<u32>,
    fqdn: Option<String>,
    groups: Vec<String>,
    is_superuser: bool,
    privileges: Privileges,
    /// `None` models an authenticator that returns no language, leaving the
    /// choice to the server's `default_language`.
    language: Option<Language>,
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
    client_instance_id: Option<u64>,
    tls_ja3: Option<String>,
    tls_ja4: Option<String>,
    tls_ja4t: Option<String>,
    tls_ja4x: Option<String>,
    tls_ja4l: Option<String>,
    ip_ttl: Option<u8>,
    tls_sni: Option<String>,
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

    pub fn client_instance_id(&self) -> Option<u64> {
        self.client_instance_id
    }

    pub fn tls_ja4(&self) -> Option<&str> {
        self.tls_ja4.as_deref()
    }

    pub fn tls_ja3(&self) -> Option<&str> {
        self.tls_ja3.as_deref()
    }

    pub fn tls_ja4x(&self) -> Option<&str> {
        self.tls_ja4x.as_deref()
    }

    pub fn tls_ja4t(&self) -> Option<&str> {
        self.tls_ja4t.as_deref()
    }

    pub fn tls_ja4l(&self) -> Option<&str> {
        self.tls_ja4l.as_deref()
    }

    pub fn ip_ttl(&self) -> Option<u8> {
        self.ip_ttl
    }

    pub fn tls_sni(&self) -> Option<&str> {
        self.tls_sni.as_deref()
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
        self.register_user_without_language(name, password, user_id, groups);
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
            None,
            None,
            None,
        );
    }

    pub fn register_invisible_user(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
    ) {
        self.users.lock().unwrap().insert(
            name.to_owned(),
            ScriptedUser {
                password: password.map(str::to_owned),
                user_id,
                fqdn: None,
                groups,
                is_superuser: false,
                privileges: Privilege::Invisible.into(),
                language: None,
                virtual_server_id: None,
                max_bandwidth: None,
            },
        );
    }

    pub fn register_invisible_superuser(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
    ) {
        self.users.lock().unwrap().insert(
            name.to_owned(),
            ScriptedUser {
                password: password.map(str::to_owned),
                user_id,
                fqdn: None,
                groups,
                is_superuser: true,
                privileges: Privilege::Invisible.into(),
                language: None,
                virtual_server_id: None,
                max_bandwidth: None,
            },
        );
    }

    /// Register (or overwrite) a regular user holding `privileges`.
    pub fn register_privileged_user(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
        privileges: impl IntoIterator<Item = Privilege>,
    ) {
        self.users.lock().unwrap().insert(
            name.to_owned(),
            ScriptedUser {
                password: password.map(str::to_owned),
                user_id,
                fqdn: None,
                groups,
                is_superuser: false,
                privileges: privileges.into_iter().collect(),
                language: None,
                virtual_server_id: None,
                max_bandwidth: None,
            },
        );
    }

    /// Replace the privileges returned for an already registered user.
    pub fn set_privileges(&self, name: &str, privileges: impl IntoIterator<Item = Privilege>) {
        if let Some(user) = self.users.lock().unwrap().get_mut(name) {
            user.privileges = privileges.into_iter().collect();
        }
    }

    /// Give an already registered user an FQDN, which the authentication
    /// result reports alongside the user id.
    pub fn set_fqdn(&self, name: &str, fqdn: Option<&str>) {
        if let Some(user) = self.users.lock().unwrap().get_mut(name) {
            user.fqdn = fqdn.map(str::to_owned);
        }
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
            None,
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
        self.register_user_in_server(name, password, user_id, groups, Some(language), None);
    }

    /// Register a user whose authentication result carries no language, so the
    /// server falls back to its `default_language`.
    pub fn register_user_without_language(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
    ) {
        self.register_user_in_server(name, password, user_id, groups, None, None);
    }

    pub fn register_user_in_server(
        &self,
        name: &str,
        password: Option<&str>,
        user_id: Option<u32>,
        groups: Vec<String>,
        language: Option<Language>,
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
        language: Option<Language>,
        virtual_server_id: Option<&str>,
        max_bandwidth: Option<u32>,
    ) {
        self.users.lock().unwrap().insert(
            name.to_owned(),
            ScriptedUser {
                password: password.map(str::to_owned),
                user_id,
                fqdn: None,
                groups,
                is_superuser,
                privileges: Privileges::empty(),
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
                client_instance_id: auxiliary_data.client_instance_id,
                tls_ja3: auxiliary_data.tls_ja3.clone(),
                tls_ja4: auxiliary_data.tls_ja4.clone(),
                tls_ja4t: auxiliary_data.tls_ja4t.clone(),
                tls_ja4x: auxiliary_data.tls_ja4x.clone(),
                tls_ja4l: auxiliary_data.tls_ja4l.clone(),
                ip_ttl: auxiliary_data.ip_ttl,
                tls_sni: auxiliary_data.tls_sni.clone(),
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
            return Err(AuthenticationRejection::new(
                shitspeak_auth::AuthenticationRejectionKind::NoSuchUser,
            ));
        };
        if let Some(expected) = entry.password.as_deref() {
            if password != Some(expected) {
                return Err(AuthenticationRejection::new(
                    shitspeak_auth::AuthenticationRejectionKind::WrongPassword,
                ));
            }
        }
        Ok(AuthenticateResult {
            auth_session_id: None,
            authenticated_until: None,
            authentication_expiry_action: Default::default(),
            user_id: entry.user_id,
            fqdn: entry.fqdn.clone(),
            display_name: Some(username.to_owned()),
            groups: entry.groups,
            is_superuser: entry.is_superuser,
            privileges: entry.privileges,
            virtual_server_id: entry.virtual_server_id,
            language: entry.language,
            max_bandwidth: entry.max_bandwidth,
            texture_url: None,
            comment_url: None,
        })
    }
}
