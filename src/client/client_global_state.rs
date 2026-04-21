use std::collections::HashSet;

use crate::protocol_version::ProtocolVersion;

#[derive(Debug, Clone)]
pub struct ClientGlobalState {
    protocol_version: Option<ProtocolVersion>, 

    current_channel_id: u32,
    last_active_timestamp: Option<std::time::Instant>,
    listening_channel_id: HashSet<u32>,

    // ── Voice / moderation state ───────────────────────────────────────────
    mute: bool,
    deaf: bool,
    suppress: bool,
    self_mute: bool,
    self_deaf: bool,
    priority_speaker: bool,
    recording: bool,
    plugin_context: Vec<u8>,
    plugin_identity: String,

    // ── Texture blob ───────────────────────────────────────────────────────
    texture_url: Option<String>,
    texture_hash: Option<String>,

    // ── Comment blob ───────────────────────────────────────────────────────
    comment_url: Option<String>,
    comment_hash: Option<String>,

    // ── User identity ─────────────────────────────────────────────────────
    user_id: Option<u32>,
    groups: HashSet<String>,
    tokens: HashSet<String>,
    display_name: Option<String>,
}

impl ClientGlobalState {
    pub fn new() -> Self {
        ClientGlobalState {
            protocol_version: None,

            current_channel_id: 0,
            last_active_timestamp: None,
            listening_channel_id: HashSet::new(),

            mute: false,
            deaf: false,
            suppress: false,
            self_mute: false,
            self_deaf: false,
            priority_speaker: false,
            recording: false,
            plugin_context: Vec::new(),
            plugin_identity: String::new(),

            texture_url: None,
            texture_hash: None,
            comment_url: None,
            comment_hash: None,

            user_id: None,
            groups: HashSet::new(),
            tokens: HashSet::new(),
            display_name: None,
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

    pub fn listen_channel(&mut self, channel_id: u32) -> bool {
        self.listening_channel_id.insert(channel_id)
    }
    
    pub fn unlisten_channel(&mut self, channel_id: u32) -> bool {
        self.listening_channel_id.remove(&channel_id)
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

    pub fn get_texture_url(&self) -> Option<&str> {
        self.texture_url.as_deref()
    }

    pub fn get_texture_hash(&self) -> Option<&str> {
        self.texture_hash.as_deref()
    }

    pub fn set_texture_blob(&mut self, url: Option<String>, hash: Option<String>) {
        self.texture_url = url;
        self.texture_hash = hash;
    }

    pub fn clear_texture_blob(&mut self) {
        self.texture_url = None;
        self.texture_hash = None;
    }

    pub fn get_comment_url(&self) -> Option<&str> {
        self.comment_url.as_deref()
    }

    pub fn get_comment_hash(&self) -> Option<&str> {
        self.comment_hash.as_deref()
    }

    pub fn set_comment_blob(&mut self, url: Option<String>, hash: Option<String>) {
        self.comment_url = url;
        self.comment_hash = hash;
    }

    pub fn clear_comment_blob(&mut self) {
        self.comment_url = None;
        self.comment_hash = None;
    }

    // ── Voice / moderation getters & setters ─────────────────────────────

    pub fn is_muted(&self) -> bool { self.mute }
    pub fn set_mute(&mut self, v: bool) { self.mute = v; }

    pub fn is_deafened(&self) -> bool { self.deaf }
    pub fn set_deaf(&mut self, v: bool) { self.deaf = v; }

    pub fn is_suppressed(&self) -> bool { self.suppress }
    pub fn set_suppress(&mut self, v: bool) { self.suppress = v; }

    pub fn is_self_muted(&self) -> bool { self.self_mute }
    pub fn set_self_mute(&mut self, v: bool) { self.self_mute = v; }

    pub fn is_self_deafened(&self) -> bool { self.self_deaf }
    pub fn set_self_deaf(&mut self, v: bool) { self.self_deaf = v; }

    pub fn is_priority_speaker(&self) -> bool { self.priority_speaker }
    pub fn set_priority_speaker(&mut self, v: bool) { self.priority_speaker = v; }

    pub fn is_recording(&self) -> bool { self.recording }
    pub fn set_recording(&mut self, v: bool) { self.recording = v; }

    pub fn get_plugin_context(&self) -> &[u8] { &self.plugin_context }
    pub fn set_plugin_context(&mut self, ctx: Vec<u8>) { self.plugin_context = ctx; }

    pub fn get_plugin_identity(&self) -> &str { &self.plugin_identity }
    pub fn set_plugin_identity(&mut self, id: String) { self.plugin_identity = id; }

    // ── User identity getters & setters ──────────────────────────────────

    pub fn get_user_id(&self) -> Option<u32> {
        self.user_id
    }

    pub fn set_user_id(&mut self, user_id: Option<u32>) {
        self.user_id = user_id;
    }

    pub fn is_registered(&self) -> bool {
        self.user_id.is_some()
    }

    pub fn get_groups(&self) -> &HashSet<String> {
        &self.groups
    }

    pub fn get_groups_mut(&mut self) -> &mut HashSet<String> {
        &mut self.groups
    }

    pub fn has_group(&self, group: &str) -> bool {
        self.groups.contains(&group.to_string())
    }

    pub fn add_group(&mut self, group: String) {
        self.groups.insert(group);
    }

    pub fn del_group(&mut self, group: &str) {
        self.groups.remove(&group.to_string());
    }

    pub fn set_groups(&mut self, groups: HashSet<String>) {
        self.groups = groups;
    }

    pub fn get_tokens(&self) -> &HashSet<String> {
        &self.tokens
    }

    pub fn add_token(&mut self, token: String) {
        self.tokens.insert(token);
    }

    pub fn del_token(&mut self, token: &str) {
        self.tokens.remove(token);
    }

    pub fn set_tokens(&mut self, tokens: HashSet<String>) {
        self.tokens = tokens;
    }

    // TODO: case insensitive
    pub fn has_token(&self, token: &str) -> bool {
        self.tokens.contains(&token.to_string())
    }

    pub fn get_display_name(&self) -> &str {
        self.display_name.as_deref().expect("Unexpected empty username; Accessing before initialization?")
    }

    pub fn get_display_name_opt(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn set_display_name(&mut self, display_name: Option<String>) {
        self.display_name = display_name;
    }
}

impl Default for ClientGlobalState {
    fn default() -> Self {
        Self::new()
    }
}
