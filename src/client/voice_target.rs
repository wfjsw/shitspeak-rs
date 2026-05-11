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

impl VoiceTargetChannel {
    pub fn new(id: u32, sub_channels: bool, links: bool, only_group: String) -> Self {
        VoiceTargetChannel {
            id,
            sub_channels,
            links,
            only_group,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn sub_channels(&self) -> bool {
        self.sub_channels
    }
    pub fn links(&self) -> bool {
        self.links
    }
    pub fn only_group(&self) -> &str {
        &self.only_group
    }
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

    pub fn sessions(&self) -> &[u32] {
        &self.sessions
    }

    pub fn channels(&self) -> &[VoiceTargetChannel] {
        &self.channels
    }

    pub fn clear(&mut self) {
        self.sessions.clear();
        self.channels.clear();
    }
}
