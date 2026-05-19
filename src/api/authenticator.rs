use std::net::IpAddr;

use crate::localization::Language;
use async_trait::async_trait;
use bytes::Bytes;

use crate::protocol_version::ProtocolVersion;

#[derive(Debug)]
pub enum AuthenticationRejection {
    WrongPassword,
    NoSuchUser,
    RetryLater,
}

#[derive(Debug)]
pub struct AuthenticateResult {
    pub user_id: Option<u32>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    /// Optional server-id scope selected by the authenticator.  Configured
    /// virtual-server entrypoints do not constrain this value.
    pub virtual_server_id: Option<String>,
    /// Preferred language for server-generated messages sent to this client.
    pub language: Language,
    /// Optional URL for the user's texture/avatar blob.
    /// When present the server fetches this URL, SHA-1s the content,
    /// and stores it in `SessionBlobStore`.
    pub texture_url: Option<String>,
    /// Optional URL for the user's comment blob.
    pub comment_url: Option<String>,
}

pub struct AuthenticateAuxiliaryData {
    pub certificate_hash: Option<Bytes>,
    pub session_id: u32,
    pub ip_address: IpAddr,
    pub version: Option<ProtocolVersion>,
    pub client_name: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExternalAuthClaims {
    pub subject: u32,
    pub username: String,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
}

/// A registered user entry returned by [`Authenticator::get_registered_users`].
#[derive(Debug, Clone)]
pub struct RegisteredUser {
    pub user_id: u32,
    pub name: String,
}

#[async_trait]
pub trait Authenticator: Send + Sync + 'static {
    async fn authenticate(
        &self,
        username: &str,
        password: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection>;

    async fn authenticate_external(
        &self,
        claims: &ExternalAuthClaims,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let _ = auxiliary_data;
        Ok(AuthenticateResult {
            user_id: Some(claims.subject),
            display_name: claims
                .display_name
                .clone()
                .or_else(|| Some(claims.username.clone())),
            groups: claims.groups.clone(),
            virtual_server_id: None,
            language: Language::default(),
            texture_url: None,
            comment_url: None,
        })
    }

    /// Select the language for server-generated text sent to this connection.
    /// Called before `authenticate`, so implementations can localize reject
    /// messages for known users even when authentication fails.
    async fn language(
        &self,
        _username: Option<&str>,
        _auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Language {
        Language::default()
    }

    // ── Optional blob helpers (default: no-op) ────────────────────────────

    /// Retrieve the raw texture bytes for a registered user.
    /// Default: always returns `None`.
    async fn get_user_texture(&self, _user_id: u32) -> Option<Bytes> {
        None
    }

    /// Retrieve the comment string for a registered user.
    /// Default: always returns `None`.
    async fn get_user_comment(&self, _user_id: u32) -> Option<String> {
        None
    }

    /// Persist a new texture for a registered user.
    /// Default: silently succeeds (no-op).
    async fn set_user_texture(&self, _user_id: u32, _data: Bytes) -> Result<(), ()> {
        Ok(())
    }

    /// Persist a new comment for a registered user.
    /// Default: silently succeeds (no-op).
    async fn set_user_comment(&self, _user_id: u32, _comment: String) -> Result<(), ()> {
        Ok(())
    }

    // ── Optional user-list helpers (default: empty / no-op) ──────────────

    /// Look up registered users by name prefix/substring.
    /// Default: returns an empty list.
    async fn get_registered_users(&self, _name_filter: &str) -> Vec<RegisteredUser> {
        Vec::new()
    }

    /// Unregister (delete) a user by ID.
    /// Default: silently succeeds (no-op).
    async fn unregister_user(&self, _user_id: u32) -> Result<(), ()> {
        Ok(())
    }
}
