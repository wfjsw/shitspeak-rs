use crate::mumble_proto::{Reject, reject::RejectType};

#[derive(Debug, Clone)]
pub struct AuthRejection {
    rejection_type: RejectType,
    reason: Option<String>,
}

impl AuthRejection {
    pub fn new(rejection_type: RejectType) -> Self {
        // TODO: populate reason based on type
        Self { rejection_type, reason: None }
    }

    pub fn because(mut self, reason: String) -> Self {
        self.reason = Some(reason);
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

impl Into<Reject> for AuthRejection {
    fn into(self) -> Reject {
        Reject {
            reason: self.reason,
            r#type: Some(self.rejection_type.into()),
        }
    }
}
