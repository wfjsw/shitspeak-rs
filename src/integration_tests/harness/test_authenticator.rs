//! A scriptable [`Authenticator`] for tests.
//!
//! Tests register users up front (with optional password and group list), then
//! the [`AuthenticatorAdapter`] satisfies the trait bound on `Server::new` while
//! delegating to the shared `Arc<TestAuthenticator>`.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::api::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
};
use crate::localization::Language;

#[derive(Debug, Clone)]
struct ScriptedUser {
    password: Option<String>,
    user_id: Option<u32>,
    groups: Vec<String>,
    language: Language,
    virtual_server_id: Option<String>,
    max_bandwidth: Option<u32>,
}

#[derive(Default)]
pub struct TestAuthenticator {
    users: Mutex<HashMap<String, ScriptedUser>>,
}

impl TestAuthenticator {
    pub fn new() -> Self {
        Self::default()
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
        _auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
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
            user_id: entry.user_id,
            display_name: Some(username.to_owned()),
            groups: entry.groups,
            virtual_server_id: entry.virtual_server_id,
            language: entry.language,
            max_bandwidth: entry.max_bandwidth,
            texture_url: None,
            comment_url: None,
        })
    }

    async fn language(
        &self,
        username: Option<&str>,
        _auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Language {
        let Some(username) = username else {
            return Language::default();
        };
        self.0
            .users
            .lock()
            .unwrap()
            .get(username)
            .map(|entry| entry.language)
            .unwrap_or_default()
    }
}
