use std::collections::HashSet;

use crate::client::user_version::UserVersion;

pub struct ClientGlobalState {
    user_id: Option<u32>,
    user_version: Option<UserVersion>, 

    current_channel_id: u32,
    last_active_timestamp: Option<std::time::Instant>,
    listening_channel_id: HashSet<u32>,
}

impl ClientGlobalState {
    pub fn new() -> Self {
        ClientGlobalState {
            user_id: None,
            user_version: None,

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
}

impl Default for ClientGlobalState {
    fn default() -> Self {
        Self::new()
    }
}
