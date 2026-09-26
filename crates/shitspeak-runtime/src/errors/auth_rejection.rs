use std::borrow::Cow;

use crate::{
    localization::{Language, Localizer, TextKey, reject_key, source_text},
    messages::encoder::{Reject, RejectType},
};

/// Why authentication was rejected. The client-facing text is resolved only
/// when the `Reject` is built for a specific client, so it is always in that
/// client's language and reflects live translation updates.
#[derive(Debug, Clone)]
enum RejectionReason {
    /// The catalog text for the rejection type.
    Default,
    /// A catalog message chosen by the server.
    Text(TextKey),
    /// Text supplied from outside the catalog, such as an authenticator's
    /// reason. Sent as-is.
    Custom(Cow<'static, str>),
}

#[derive(Debug, Clone)]
pub struct AuthRejection {
    rejection_type: RejectType,
    reason: RejectionReason,
}

impl AuthRejection {
    pub fn new(rejection_type: RejectType) -> Self {
        Self {
            rejection_type,
            reason: RejectionReason::Default,
        }
    }

    /// Use a catalog message as the reason.
    pub fn because_text(mut self, key: TextKey) -> Self {
        self.reason = RejectionReason::Text(key);
        self
    }

    /// Use `reason` verbatim, e.g. text provided by an authenticator.
    pub fn because(mut self, reason: impl Into<Cow<'static, str>>) -> Self {
        self.reason = RejectionReason::Custom(reason.into());
        self
    }

    pub fn rejection_type(&self) -> RejectType {
        self.rejection_type
    }

    /// The reason in `language`.
    pub fn reason_in(&self, localizer: &Localizer, language: &Language) -> Cow<'static, str> {
        match &self.reason {
            RejectionReason::Default => localizer.reject_reason(language, self.rejection_type),
            RejectionReason::Text(key) => localizer.text(language, *key),
            RejectionReason::Custom(reason) => reason.clone(),
        }
    }

    /// The `Reject` message for a client that uses `language`.
    pub fn to_reject(&self, localizer: &Localizer, language: &Language) -> Reject {
        Reject {
            r#type: Some(self.rejection_type),
            reason: Some(self.reason_in(localizer, language).into_owned()),
        }
    }

    /// English reason, for logs.
    fn source_reason(&self) -> &str {
        match &self.reason {
            RejectionReason::Default => source_text(reject_key(self.rejection_type)),
            RejectionReason::Text(key) => source_text(key.key()),
            RejectionReason::Custom(reason) => reason,
        }
    }
}

impl std::fmt::Display for AuthRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authentication rejected: {}", self.source_reason())
    }
}

impl std::error::Error for AuthRejection {}

#[cfg(test)]
mod tests {
    use super::*;

    fn spanish() -> Language {
        Language::parse("es").unwrap()
    }

    #[test]
    fn reasons_are_resolved_in_the_requested_language() {
        let localizer = Localizer::bundled();

        let default = AuthRejection::new(RejectType::WrongUserPw);
        assert_eq!(
            default.to_reject(&localizer, &spanish()).reason.as_deref(),
            Some("Usuario o contraseña incorrectos")
        );

        let text = AuthRejection::new(RejectType::None).because_text(TextKey::MissingRequiredGroup);
        assert_eq!(
            text.reason_in(&localizer, &Language::ENGLISH),
            "Missing required group membership"
        );
        assert_ne!(
            text.reason_in(&localizer, &spanish()),
            "Missing required group membership"
        );

        let custom = AuthRejection::new(RejectType::WrongUserPw).because("Account locked");
        assert_eq!(custom.reason_in(&localizer, &spanish()), "Account locked");
    }

    #[test]
    fn display_uses_english_for_logs() {
        assert_eq!(
            AuthRejection::new(RejectType::ServerFull).to_string(),
            "Authentication rejected: The server is full"
        );
    }
}
