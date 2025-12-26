use std::collections::HashSet;

use crate::client::user_version::UserVersion;

pub struct ClientLocalState {
    synced: bool,
    authenticated: bool,

    last_active_timestamp: Option<std::time::Instant>,
}

impl ClientLocalState {
    pub fn new() -> Self {
        ClientLocalState {
            synced: false,
            authenticated: false,

            last_active_timestamp: None,
        }
    }


}

impl Default for ClientLocalState {
    fn default() -> Self {
        Self::new()
    }
}
