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

#[derive(Debug, Clone)]
struct ScriptedUser {
    password: Option<String>,
    user_id: Option<u32>,
    groups: Vec<String>,
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
        self.users.lock().unwrap().insert(
            name.to_owned(),
            ScriptedUser {
                password: password.map(str::to_owned),
                user_id,
                groups,
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
            texture_url: None,
            comment_url: None,
        })
    }
}
