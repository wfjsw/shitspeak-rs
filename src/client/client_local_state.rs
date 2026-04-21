use std::collections::HashSet;

use crate::client::user_version::UserVersion;

pub struct ClientLocalState {
    synced: bool,
    authenticated: bool,
    supports_opus: bool,

    last_active_timestamp: Option<std::time::Instant>,
}

impl ClientLocalState {
    pub fn new() -> Self {
        ClientLocalState {
            synced: false,
            authenticated: false,
            supports_opus: false,

            last_active_timestamp: None,
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
}

impl Default for ClientLocalState {
    fn default() -> Self {
        Self::new()
    }
}
