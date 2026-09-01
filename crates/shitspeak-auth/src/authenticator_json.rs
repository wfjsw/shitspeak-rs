use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shitspeak_core::ProtocolVersion;

use crate::Language;

use super::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationExpiryAction,
    AuthenticationRejection, ExternalAuthClaims, canonical_authenticator_ip,
};

#[derive(Serialize)]
pub(crate) struct AuthenticatorJsonAuthenticateRequest {
    username: String,
    password: Option<String>,
    auxiliary_data: AuthenticatorJsonAuxiliaryData,
}

impl AuthenticatorJsonAuthenticateRequest {
    pub(crate) fn new(
        username: String,
        password: Option<String>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Self {
        Self {
            username,
            password,
            auxiliary_data: AuthenticatorJsonAuxiliaryData::from(auxiliary_data),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct AuthenticatorJsonExternalAuthenticateRequest {
    claims: AuthenticatorJsonExternalAuthClaims,
    auxiliary_data: AuthenticatorJsonAuxiliaryData,
}

impl AuthenticatorJsonExternalAuthenticateRequest {
    pub(crate) fn new(
        claims: &ExternalAuthClaims,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Self {
        Self {
            claims: AuthenticatorJsonExternalAuthClaims::from(claims),
            auxiliary_data: AuthenticatorJsonAuxiliaryData::from(auxiliary_data),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct ExecAuthenticatorJsonRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<u64>,
    #[serde(flatten)]
    command: ExecAuthenticatorJsonCommand,
}

impl ExecAuthenticatorJsonRequest {
    pub(crate) fn with_request_id(mut self, request_id: u64) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExecAuthenticatorJsonCommand {
    Authenticate {
        username: String,
        password: Option<String>,
        auxiliary_data: AuthenticatorJsonAuxiliaryData,
    },
    AuthenticateExternal {
        claims: AuthenticatorJsonExternalAuthClaims,
        auxiliary_data: AuthenticatorJsonAuxiliaryData,
    },
}

impl ExecAuthenticatorJsonRequest {
    pub(crate) fn authenticate(
        username: &str,
        password: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Self {
        Self {
            request_id: None,
            command: ExecAuthenticatorJsonCommand::Authenticate {
                username: username.to_owned(),
                password: password.map(ToOwned::to_owned),
                auxiliary_data: AuthenticatorJsonAuxiliaryData::from(auxiliary_data),
            },
        }
    }

    pub(crate) fn authenticate_external(
        claims: &ExternalAuthClaims,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Self {
        Self {
            request_id: None,
            command: ExecAuthenticatorJsonCommand::AuthenticateExternal {
                claims: AuthenticatorJsonExternalAuthClaims::from(claims),
                auxiliary_data: AuthenticatorJsonAuxiliaryData::from(auxiliary_data),
            },
        }
    }
}

#[derive(Serialize)]
pub(crate) struct AuthenticatorJsonAuxiliaryData {
    certificate_hash_base64: Option<String>,
    session_id: u32,
    ip_address: IpAddr,
    tls_ja3: Option<String>,
    tls_ja4: Option<String>,
    tls_ja4t: Option<String>,
    tls_ja4x: Option<String>,
    tls_ja4l: Option<String>,
    tls_sni: Option<String>,
    proxy_server_address: Option<SocketAddr>,
    packet_capture_backends: Vec<String>,
    packet_capture_backend: Option<String>,
    uses_proxy_protocol: bool,
    version: Option<ProtocolVersion>,
    client_name: Option<String>,
    os_name: Option<String>,
    os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_session_id: Option<String>,
}

impl From<&AuthenticateAuxiliaryData> for AuthenticatorJsonAuxiliaryData {
    fn from(value: &AuthenticateAuxiliaryData) -> Self {
        Self {
            certificate_hash_base64: value
                .certificate_hash
                .as_ref()
                .map(|hash| BASE64_STANDARD.encode(hash)),
            session_id: value.session_id,
            ip_address: canonical_authenticator_ip(value.ip_address),
            tls_ja3: value.tls_ja3.clone(),
            tls_ja4: value.tls_ja4.clone(),
            tls_ja4t: value.tls_ja4t.clone(),
            tls_ja4x: value.tls_ja4x.clone(),
            tls_ja4l: value.tls_ja4l.clone(),
            tls_sni: value.tls_sni.clone(),
            proxy_server_address: value.proxy_server_address,
            packet_capture_backends: value.packet_capture_backends.clone(),
            packet_capture_backend: value.packet_capture_backend.clone(),
            uses_proxy_protocol: value.uses_proxy_protocol,
            version: value.version,
            client_name: value.client_name.clone(),
            os_name: value.os_name.clone(),
            os_version: value.os_version.clone(),
            auth_session_id: value.auth_session_id.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct AuthenticatorJsonExternalAuthClaims {
    subject: u32,
    username: String,
    display_name: Option<String>,
    groups: Vec<String>,
}

impl From<&ExternalAuthClaims> for AuthenticatorJsonExternalAuthClaims {
    fn from(value: &ExternalAuthClaims) -> Self {
        Self {
            subject: value.subject,
            username: value.username.clone(),
            display_name: value.display_name.clone(),
            groups: value.groups.clone(),
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct AuthenticatorJsonAuthenticateResponse {
    #[serde(default = "default_false")]
    accepted: bool,
    #[serde(default)]
    rejection: Option<String>,
    #[serde(default)]
    user_id: Option<u32>,
    #[serde(default)]
    fqdn: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    is_superuser: bool,
    #[serde(default)]
    invisible: bool,
    #[serde(default)]
    virtual_server_id: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    max_bandwidth: Option<u32>,
    #[serde(default)]
    texture_url: Option<String>,
    #[serde(default)]
    comment_url: Option<String>,
    #[serde(default)]
    auth_session_id: Option<String>,
    #[serde(default)]
    authenticated_until: Option<DateTime<Utc>>,
    #[serde(default)]
    authentication_expiry_action: AuthenticationExpiryAction,
}

impl AuthenticatorJsonAuthenticateResponse {
    pub(crate) fn into_authenticate_result(
        self,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        if !self.accepted {
            return Err(match self.rejection.as_deref() {
                Some("no_such_user") | Some("invalid_username") => {
                    AuthenticationRejection::NoSuchUser
                }
                Some("wrong_password") => AuthenticationRejection::WrongPassword,
                _ => AuthenticationRejection::RetryLater,
            });
        }
        Ok(AuthenticateResult {
            user_id: self.user_id,
            fqdn: self.fqdn,
            display_name: self.display_name,
            groups: self.groups,
            is_superuser: self.is_superuser,
            invisible: self.invisible,
            virtual_server_id: self.virtual_server_id,
            language: self
                .language
                .as_deref()
                .map(Language::from_code)
                .unwrap_or_default(),
            max_bandwidth: self.max_bandwidth,
            texture_url: self.texture_url,
            comment_url: self.comment_url,
            auth_session_id: self.auth_session_id,
            authenticated_until: self.authenticated_until,
            authentication_expiry_action: self.authentication_expiry_action,
        })
    }
}

pub(crate) fn authenticate_result_from_external_claims(
    claims: &ExternalAuthClaims,
) -> AuthenticateResult {
    AuthenticateResult {
        user_id: Some(claims.subject),
        fqdn: None,
        display_name: claims
            .display_name
            .clone()
            .or_else(|| Some(claims.username.clone())),
        groups: claims.groups.clone(),
        is_superuser: false,
        invisible: false,
        virtual_server_id: None,
        language: Language::default(),
        max_bandwidth: None,
        texture_url: None,
        comment_url: None,
        auth_session_id: None,
        authenticated_until: None,
        authentication_expiry_action: AuthenticationExpiryAction::default(),
    }
}

fn default_false() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_response_maps_rejection_reasons() {
        let response: AuthenticatorJsonAuthenticateResponse =
            serde_json::from_str(r#"{"accepted":false,"rejection":"wrong_password"}"#).unwrap();
        assert!(matches!(
            response.into_authenticate_result(),
            Err(AuthenticationRejection::WrongPassword)
        ));

        let response: AuthenticatorJsonAuthenticateResponse =
            serde_json::from_str(r#"{"accepted":false,"rejection":"invalid_username"}"#).unwrap();
        assert!(matches!(
            response.into_authenticate_result(),
            Err(AuthenticationRejection::NoSuchUser)
        ));

        let response: AuthenticatorJsonAuthenticateResponse =
            serde_json::from_str(r#"{"accepted":false,"rejection":"temporarily_down"}"#).unwrap();
        assert!(matches!(
            response.into_authenticate_result(),
            Err(AuthenticationRejection::RetryLater)
        ));
    }

    #[test]
    fn authenticate_response_defaults_to_reject() {
        // Fail closed: a malformed/error-shaped backend response that omits
        // `accepted` must never be treated as a successful login.
        let response: AuthenticatorJsonAuthenticateResponse =
            serde_json::from_str(r#"{"user_id":7,"display_name":"alice"}"#).unwrap();
        assert!(matches!(
            response.into_authenticate_result(),
            Err(AuthenticationRejection::RetryLater)
        ));

        let response: AuthenticatorJsonAuthenticateResponse =
            serde_json::from_str(r#"{"error":"db down"}"#).unwrap();
        assert!(matches!(
            response.into_authenticate_result(),
            Err(AuthenticationRejection::RetryLater)
        ));
    }

    #[test]
    fn authenticate_response_maps_fqdn() {
        let response: AuthenticatorJsonAuthenticateResponse =
            serde_json::from_str(r#"{"accepted":true,"user_id":7,"fqdn":"alice@example.test"}"#)
                .unwrap();

        let result = response.into_authenticate_result().unwrap();

        assert_eq!(result.user_id, Some(7));
        assert_eq!(result.fqdn.as_deref(), Some("alice@example.test"));
    }

    #[test]
    fn authenticate_response_maps_session_expiry_fields() {
        let response: AuthenticatorJsonAuthenticateResponse = serde_json::from_str(
            r#"{
                "accepted":true,
                "auth_session_id":"auth-session-7",
                "authenticated_until":"2030-01-02T03:04:05Z",
                "authentication_expiry_action":"reauth"
            }"#,
        )
        .unwrap();
        let result = response.into_authenticate_result().unwrap();

        assert_eq!(result.auth_session_id.as_deref(), Some("auth-session-7"));
        assert_eq!(
            result.authenticated_until,
            Some("2030-01-02T03:04:05Z".parse().unwrap())
        );
        assert_eq!(
            result.authentication_expiry_action,
            AuthenticationExpiryAction::Reauth
        );
    }

    #[test]
    fn auxiliary_data_serializes_auth_session_id() {
        let mut auxiliary = AuthenticateAuxiliaryData {
            certificate_hash: None,
            session_id: 7,
            ip_address: "127.0.0.1".parse().unwrap(),
            tls_ja3: None,
            tls_ja4: None,
            tls_ja4t: None,
            tls_ja4x: None,
            tls_ja4l: None,
            tls_sni: None,
            proxy_server_address: None,
            packet_capture_backends: Vec::new(),
            packet_capture_backend: None,
            uses_proxy_protocol: false,
            version: None,
            client_name: None,
            os_name: None,
            os_version: None,
            auth_session_id: Some("auth-session-7".to_owned()),
        };

        let json = serde_json::to_value(AuthenticatorJsonAuxiliaryData::from(&auxiliary)).unwrap();
        assert_eq!(json["auth_session_id"], "auth-session-7");

        auxiliary.auth_session_id = None;
        let json = serde_json::to_value(AuthenticatorJsonAuxiliaryData::from(&auxiliary)).unwrap();
        assert!(json.get("auth_session_id").is_none());
    }
}
