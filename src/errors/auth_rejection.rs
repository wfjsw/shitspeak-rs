use std::borrow::Cow;

use crate::messages::encoder::RejectType;

#[derive(Debug, Clone)]
pub struct AuthRejection {
    rejection_type: RejectType,
    reason: Option<Cow<'static, str>>,
}

impl AuthRejection {
    pub fn new(rejection_type: RejectType) -> Self {
        // TODO: populate reason based on type
        Self {
            rejection_type,
            reason: None,
        }
    }

    pub fn because(mut self, reason: impl Into<Cow<'static, str>>) -> Self {
        self.reason = Some(reason.into());
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

impl Into<crate::messages::encoder::Reject> for AuthRejection {
    fn into(self) -> crate::messages::encoder::Reject {
        crate::messages::encoder::Reject {
            r#type: Some(self.rejection_type),
            reason: self.reason.map(Cow::into_owned),
        }
    }
}
