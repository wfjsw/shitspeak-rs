use std::borrow::Cow;

use crate::{
    localization::{Language, reject_reason},
    messages::encoder::RejectType,
};

#[derive(Debug, Clone)]
pub struct AuthRejection {
    rejection_type: RejectType,
    reason: Option<Cow<'static, str>>,
    reason_is_default: bool,
}

impl AuthRejection {
    pub fn new(rejection_type: RejectType) -> Self {
        Self::new_with_language(rejection_type, Language::default())
    }

    pub fn new_with_language(rejection_type: RejectType, language: Language) -> Self {
        Self {
            rejection_type,
            reason: Some(reject_reason(language, rejection_type)),
            reason_is_default: true,
        }
    }

    pub fn localized(mut self, language: Language) -> Self {
        if self.reason_is_default {
            self.reason = Some(reject_reason(language, self.rejection_type));
        }
        self
    }

    pub fn because(mut self, reason: impl Into<Cow<'static, str>>) -> Self {
        self.reason = Some(reason.into());
        self.reason_is_default = false;
        self
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

impl std::fmt::Display for AuthRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            Some(reason) => write!(f, "Authentication rejected: {}", reason),
            None => write!(f, "Authentication rejected"),
        }
    }
}

impl std::error::Error for AuthRejection {}

impl Into<shitspeak_messages::messages::encoder::Reject> for AuthRejection {
    fn into(self) -> shitspeak_messages::messages::encoder::Reject {
        shitspeak_messages::messages::encoder::Reject {
            r#type: Some(self.rejection_type),
            reason: self.reason.map(Cow::into_owned),
        }
    }
}
