use std::collections::{HashSet};

pub struct SessionStates {
    channel_id: u32,
    self_mute: bool,
    self_deaf: bool,
    mute: bool,
    deaf: bool,
    suppress: bool,
    priority_speaker: bool,
    recording: bool,
    plugin_context: Vec<u8>,
    plugin_identity: String,
    listening_channel_id: HashSet<u32>,
}
