use std::collections::HashSet;

use crate::client::user_version::UserVersion;

pub struct ClientLocalState {
    synced: bool,
    authenticated: bool,
    supports_opus: bool,

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
