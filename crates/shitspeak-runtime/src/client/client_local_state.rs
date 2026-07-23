use chrono::{DateTime, Utc};

use crate::localization::Language;
use shitspeak_auth::AuthenticationExpiryAction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExpiredAuthenticationAction {
    Reauthenticate { auth_session_id: Option<String> },
    Kick,
    Deregister,
}

pub struct ClientLocalState {
    synced: bool,
    authenticated: bool,
    supports_opus: bool,
    language: Language,
    max_bandwidth: Option<u32>,

    auth_session_id: Option<String>,
    authenticated_until: Option<DateTime<Utc>>,
    authentication_expiry_action: AuthenticationExpiryAction,
    reauthentication_in_progress: bool,

    last_active_timestamp: Option<std::time::Instant>,

    release: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
}

impl ClientLocalState {
    pub fn new() -> Self {
        ClientLocalState {
            synced: false,
            authenticated: false,
            supports_opus: false,
            language: Language::default(),
            max_bandwidth: None,

            auth_session_id: None,
            authenticated_until: None,
            authentication_expiry_action: AuthenticationExpiryAction::Kick,
            reauthentication_in_progress: false,

            last_active_timestamp: None,

            release: None,
            os: None,
            os_version: None,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn set_authenticated(&mut self, value: bool) {
        self.authenticated = value;
    }

    pub fn supports_opus(&self) -> bool {
        self.supports_opus
    }

    pub fn set_supports_opus(&mut self, value: bool) {
        self.supports_opus = value;
    }

    pub fn language(&self) -> Language {
        self.language
    }

    pub fn set_language(&mut self, language: Language) {
        self.language = language;
    }

    pub fn max_bandwidth(&self) -> Option<u32> {
        self.max_bandwidth
    }

    pub fn set_max_bandwidth(&mut self, max_bandwidth: Option<u32>) {
        self.max_bandwidth = max_bandwidth;
    }

    pub fn auth_session_id(&self) -> Option<&str> {
        self.auth_session_id.as_deref()
    }

    pub fn authenticated_until(&self) -> Option<DateTime<Utc>> {
        self.authenticated_until
    }

    pub fn authentication_expiry_action(&self) -> AuthenticationExpiryAction {
        self.authentication_expiry_action
    }

    pub fn is_reauthentication_in_progress(&self) -> bool {
        self.reauthentication_in_progress
    }

    pub fn set_authentication_expiry(
        &mut self,
        auth_session_id: Option<String>,
        authenticated_until: Option<DateTime<Utc>>,
        authentication_expiry_action: AuthenticationExpiryAction,
    ) {
        self.auth_session_id = auth_session_id;
        self.authenticated_until = authenticated_until;
        self.authentication_expiry_action = authentication_expiry_action;
        self.reauthentication_in_progress = false;
    }

    pub fn complete_authentication(
        &mut self,
        auth_session_id: Option<String>,
        authenticated_until: Option<DateTime<Utc>>,
        authentication_expiry_action: AuthenticationExpiryAction,
    ) {
        self.set_authentication_expiry(
            auth_session_id,
            authenticated_until,
            authentication_expiry_action,
        );
        self.authenticated = true;
    }

    pub(crate) fn take_expired_authentication(
        &mut self,
        now: DateTime<Utc>,
        allow_reauth: bool,
    ) -> Option<ExpiredAuthenticationAction> {
        if !self.authenticated
            || self.reauthentication_in_progress
            || self
                .authenticated_until
                .is_none_or(|deadline| now < deadline)
            || (!allow_reauth
                && self.authentication_expiry_action == AuthenticationExpiryAction::Reauth)
        {
            return None;
        }

        match self.authentication_expiry_action {
            AuthenticationExpiryAction::Reauth => {
                self.reauthentication_in_progress = true;
                Some(ExpiredAuthenticationAction::Reauthenticate {
                    auth_session_id: self.auth_session_id.clone(),
                })
            }
            AuthenticationExpiryAction::Kick => {
                self.authenticated_until = None;
                self.authenticated = false;
                Some(ExpiredAuthenticationAction::Kick)
            }
            AuthenticationExpiryAction::Deregister => {
                self.authenticated_until = None;
                Some(ExpiredAuthenticationAction::Deregister)
            }
        }
    }

    pub fn get_release(&self) -> Option<&str> {
        self.release.as_deref()
    }

    pub fn set_release(&mut self, release: Option<String>) {
        if release.is_none() && self.release.is_some() {
            return;
        }

        self.release = match release {
            Some(r) => Some(r.chars().take(100).collect()),
            None => None,
        }
    }

    pub fn get_os_name(&self) -> Option<&str> {
        self.os.as_deref()
    }

    pub fn set_os(&mut self, os: Option<String>) {
        if os.is_none() && self.os.is_some() {
            return;
        }

        self.os = match os {
            Some(o) => Some(o.chars().take(40).collect()),
            None => None,
        }
    }

    pub fn get_os_version(&self) -> Option<&str> {
        self.os_version.as_deref()
    }

    pub fn set_os_version(&mut self, os_version: Option<String>) {
        if os_version.is_none() && self.os_version.is_some() {
            return;
        }

        self.os_version = match os_version {
            Some(v) => Some(v.chars().take(60).collect()),
            None => None,
        }
    }
}

impl Default for ClientLocalState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};

    use super::{ClientLocalState, ExpiredAuthenticationAction};
    use shitspeak_auth::AuthenticationExpiryAction;

    fn deadline() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0)
            .single()
            .unwrap()
    }

    #[test]
    fn authentication_expiry_before_deadline_is_not_claimed() {
        let mut state = ClientLocalState::new();
        state.set_authenticated(true);
        state.set_authentication_expiry(
            Some("auth-session".to_owned()),
            Some(deadline()),
            AuthenticationExpiryAction::Kick,
        );

        assert_eq!(
            state
                .take_expired_authentication(deadline() - chrono::Duration::milliseconds(1), true,),
            None
        );
        assert!(state.is_authenticated());
        assert_eq!(state.authenticated_until(), Some(deadline()));
    }

    #[test]
    fn authentication_expiry_is_not_claimed_before_initial_authentication_completes() {
        let mut state = ClientLocalState::new();
        state.set_authentication_expiry(
            Some("auth-session".to_owned()),
            Some(deadline()),
            AuthenticationExpiryAction::Kick,
        );

        assert_eq!(
            state.take_expired_authentication(deadline() + chrono::Duration::seconds(1), true),
            None
        );
        assert!(!state.is_authenticated());
        assert_eq!(state.authenticated_until(), Some(deadline()));
    }

    #[test]
    fn authentication_expiry_at_deadline_is_claimed_only_once() {
        let mut state = ClientLocalState::new();
        state.set_authenticated(true);
        state.set_authentication_expiry(None, Some(deadline()), AuthenticationExpiryAction::Kick);

        assert_eq!(
            state.take_expired_authentication(deadline(), true),
            Some(ExpiredAuthenticationAction::Kick)
        );
        assert!(!state.is_authenticated());
        assert_eq!(state.authenticated_until(), None);
        assert_eq!(state.take_expired_authentication(deadline(), true), None);
    }

    #[test]
    fn reauthentication_claim_carries_session_and_blocks_duplicate_claims() {
        let mut state = ClientLocalState::new();
        state.set_authenticated(true);
        state.set_authentication_expiry(
            Some("auth-session".to_owned()),
            Some(deadline()),
            AuthenticationExpiryAction::Reauth,
        );

        assert_eq!(
            state.take_expired_authentication(deadline() + chrono::Duration::seconds(1), true,),
            Some(ExpiredAuthenticationAction::Reauthenticate {
                auth_session_id: Some("auth-session".to_owned()),
            })
        );
        assert!(state.is_authenticated());
        assert!(state.is_reauthentication_in_progress());
        assert_eq!(state.auth_session_id(), Some("auth-session"));
        assert_eq!(state.authenticated_until(), Some(deadline()));
        assert_eq!(
            state.authentication_expiry_action(),
            AuthenticationExpiryAction::Reauth
        );
        assert_eq!(
            state.take_expired_authentication(deadline() + chrono::Duration::seconds(2), true,),
            None
        );
    }

    #[test]
    fn deferred_reauthentication_preserves_deadline_and_authenticated_state() {
        let mut state = ClientLocalState::new();
        state.complete_authentication(
            Some("auth-session".to_owned()),
            Some(deadline()),
            AuthenticationExpiryAction::Reauth,
        );

        assert_eq!(
            state.take_expired_authentication(deadline() + chrono::Duration::seconds(1), false),
            None
        );
        assert!(state.is_authenticated());
        assert!(!state.is_reauthentication_in_progress());
        assert_eq!(state.authenticated_until(), Some(deadline()));

        assert_eq!(
            state.take_expired_authentication(deadline() + chrono::Duration::seconds(2), true),
            Some(ExpiredAuthenticationAction::Reauthenticate {
                auth_session_id: Some("auth-session".to_owned()),
            })
        );
        assert!(state.is_authenticated());
    }

    #[test]
    fn successful_authentication_metadata_clears_reauthentication_in_progress() {
        let mut state = ClientLocalState::new();
        state.set_authenticated(true);
        state.set_authentication_expiry(
            Some("old-session".to_owned()),
            Some(deadline()),
            AuthenticationExpiryAction::Reauth,
        );
        assert!(
            state
                .take_expired_authentication(deadline(), true)
                .is_some()
        );

        let next_deadline = deadline() + chrono::Duration::hours(1);
        state.set_authentication_expiry(
            Some("new-session".to_owned()),
            Some(next_deadline),
            AuthenticationExpiryAction::Deregister,
        );

        assert!(!state.is_reauthentication_in_progress());
        assert_eq!(state.auth_session_id(), Some("new-session"));
        assert_eq!(state.authenticated_until(), Some(next_deadline));
        assert_eq!(
            state.authentication_expiry_action(),
            AuthenticationExpiryAction::Deregister
        );
    }

    #[test]
    fn deregister_claim_preserves_authenticated_connection_state() {
        let mut state = ClientLocalState::new();
        state.set_authenticated(true);
        state.set_authentication_expiry(
            None,
            Some(deadline()),
            AuthenticationExpiryAction::Deregister,
        );

        assert_eq!(
            state.take_expired_authentication(deadline(), true),
            Some(ExpiredAuthenticationAction::Deregister)
        );
        assert!(state.is_authenticated());
        assert!(!state.is_reauthentication_in_progress());
    }

    #[test]
    fn authentication_without_deadline_never_expires() {
        let mut state = ClientLocalState::new();
        state.set_authenticated(true);
        state.set_authentication_expiry(
            Some("auth-session".to_owned()),
            None,
            AuthenticationExpiryAction::Kick,
        );

        assert_eq!(state.take_expired_authentication(deadline(), true), None);
        assert!(state.is_authenticated());
        assert_eq!(state.auth_session_id(), Some("auth-session"));
    }
}
