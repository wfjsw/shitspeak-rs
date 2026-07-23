use std::net::IpAddr;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shitspeak_core::ProtocolVersion;

use crate::Language;

pub fn canonical_authenticator_ip(ip_address: IpAddr) -> IpAddr {
    match ip_address {
        IpAddr::V4(_) => ip_address,
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ipv6)),
    }
}

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
    pub is_superuser: bool,
    /// Optional server-id scope selected by the authenticator.  Configured
    /// virtual-server entrypoints do not constrain this value.
    pub virtual_server_id: Option<String>,
    /// Preferred language for server-generated messages sent to this client.
    pub language: Language,
    /// Optional per-client maximum bandwidth advertised to the authenticated
    /// client. `None` uses the server-wide `max_bandwidth` config value.
    pub max_bandwidth: Option<u32>,
    /// Optional URL for the user's texture/avatar blob.
    /// When present the server fetches this URL, SHA-1s the content,
    /// and stores it in `SessionBlobStore`.
    pub texture_url: Option<String>,
    /// Optional URL for the user's comment blob.
    pub comment_url: Option<String>,
    /// Opaque authentication-session identifier returned by the authenticator.
    pub auth_session_id: Option<String>,
    /// Absolute time at which this authentication result expires.
    pub authenticated_until: Option<DateTime<Utc>>,
    /// Action to take when `authenticated_until` has passed.
    pub authentication_expiry_action: AuthenticationExpiryAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationExpiryAction {
    Reauth,
    #[default]
    Kick,
    Deregister,
}

#[derive(Clone)]
pub struct AuthenticateAuxiliaryData {
    pub certificate_hash: Option<Bytes>,
    pub session_id: u32,
    pub ip_address: IpAddr,
    pub tls_ja4: Option<String>,
    pub uses_proxy_protocol: bool,
    pub version: Option<ProtocolVersion>,
    pub client_name: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    /// Opaque authentication-session identifier from the previous successful
    /// authentication, when this call is a reauthentication.
    pub auth_session_id: Option<String>,
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
            is_superuser: false,
            virtual_server_id: None,
            language: Language::default(),
            max_bandwidth: None,
            texture_url: None,
            comment_url: None,
            auth_session_id: None,
            authenticated_until: None,
            authentication_expiry_action: AuthenticationExpiryAction::default(),
        })
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::canonical_authenticator_ip;

    #[test]
    fn canonical_authenticator_ip_unmaps_ipv4_mapped_ipv6() {
        let mapped = IpAddr::V6(Ipv6Addr::from([0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001]));

        assert_eq!(
            canonical_authenticator_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn canonical_authenticator_ip_keeps_native_ipv6() {
        let native = IpAddr::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(canonical_authenticator_ip(native), native);
    }
}
