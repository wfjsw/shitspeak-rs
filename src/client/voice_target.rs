pub struct VoiceTarget {
    sessions: Vec<u32>,
    channels: Vec<VoiceTargetChannel>,
}


pub struct VoiceTargetChannel {
    id: u32,
    sub_channels: bool,
    links: bool,
    only_group: String,
}

impl VoiceTarget {
    pub fn new() -> Self {
        VoiceTarget {
            sessions: Vec::new(),
            channels: Vec::new(),
        }
    }

    pub fn add_session(&mut self, session: u32) {
        self.sessions.push(session);
    }

    pub fn add_channel(&mut self, channel: VoiceTargetChannel) {
        self.channels.push(channel);
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.channels.is_empty()
    }
}
