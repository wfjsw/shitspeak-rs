use std::collections::HashSet;

use crate::{client::user_version::UserVersion, protocol_version::ProtocolVersion};

pub struct ClientGlobalState {
    user_id: Option<u32>,
    
    protocol_version: Option<ProtocolVersion>, 
    release: Option<String>,
    os: Option<String>,
    os_version: Option<String>,

    current_channel_id: u32,
    last_active_timestamp: Option<std::time::Instant>,
    listening_channel_id: HashSet<u32>,
}

impl ClientGlobalState {
    pub fn new() -> Self {
        ClientGlobalState {
            user_id: None,

            protocol_version: None,
            release: None,
            os: None,
            os_version: None,

            current_channel_id: 0,
            last_active_timestamp: None,
            listening_channel_id: HashSet::new(),
        }
    }

    pub fn get_user_id(&self) -> Option<u32> {
        self.user_id
    }

    pub fn set_user_id(&mut self, user_id: Option<u32>) {
        self.user_id = user_id;
    }

    pub fn set_current_channel_id(&mut self, channel_id: u32) {
        self.current_channel_id = channel_id;
    }

    pub fn get_current_channel_id(&self) -> u32 {
        self.current_channel_id
    }

    pub fn get_listening_channel_id(&self) -> &HashSet<u32> {
        &self.listening_channel_id
    }

    pub fn listen_channel(&mut self, channel_id: u32) {
        self.listening_channel_id.insert(channel_id);
    }
    
    pub fn unlisten_channel(&mut self, channel_id: u32) {
        self.listening_channel_id.remove(&channel_id);
    }

    pub fn is_listening_channel(&self, channel_id: u32) -> bool {
        self.listening_channel_id.contains(&channel_id)
    }

    pub fn get_protocol_version(&self) -> Option<ProtocolVersion> {
        self.protocol_version.clone()
    }

    pub fn set_protocol_version(&mut self, version: Option<ProtocolVersion>) {
        if self.protocol_version.is_some() {
            return;
        }
        self.protocol_version = match version {
            None => Some(ProtocolVersion::new(1, 2, 0)),
            Some(v) => Some(v),
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

impl Default for ClientGlobalState {
    fn default() -> Self {
        Self::new()
    }
}
