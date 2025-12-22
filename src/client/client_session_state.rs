use std::collections::HashSet;

pub struct ClientSessionState {
    current_channel_id: u32,
    last_active_timestamp: Option<std::time::Instant>,
    listening_channel_id: HashSet<u32>,
}

impl ClientSessionState {
    pub fn new(initial_channel_id: u32) -> Self {
        ClientSessionState {
            current_channel_id: initial_channel_id,
            last_active_timestamp: None,
            listening_channel_id: HashSet::new(),
        }
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
