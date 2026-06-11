use std::collections::HashSet;

use bytes::Bytes;

use crate::client::state_log::ClientGlobalStateDelta;

#[derive(Debug, Clone)]
pub struct ClientGlobalState {
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
    plugin_context: Bytes,
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
    is_superuser: bool,
    tokens: HashSet<String>,
    display_name: Option<String>,
    acl_generation: u64,

    delta_recording: bool,
    pending_delta: ClientGlobalStateDelta,
}

impl ClientGlobalState {
    pub fn new() -> Self {
        ClientGlobalState {
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
            plugin_context: Bytes::new(),
            plugin_identity: String::new(),

            texture_url: None,
            texture_hash: None,
            comment_url: None,
            comment_hash: None,

            user_id: None,
            groups: HashSet::new(),
            is_superuser: false,
            tokens: HashSet::new(),
            display_name: None,
            acl_generation: 0,

            delta_recording: false,
            pending_delta: ClientGlobalStateDelta::default(),
        }
    }

    pub(crate) fn begin_delta_recording(&mut self) {
        self.delta_recording = true;
        self.pending_delta = ClientGlobalStateDelta::default();
    }

    pub(crate) fn finish_delta_recording(&mut self) -> ClientGlobalStateDelta {
        self.delta_recording = false;
        std::mem::take(&mut self.pending_delta)
    }

    pub(crate) fn cancel_delta_recording(&mut self) {
        self.delta_recording = false;
        self.pending_delta = ClientGlobalStateDelta::default();
    }

    pub fn set_current_channel_id(&mut self, channel_id: u32) -> bool {
        if self.current_channel_id == channel_id {
            return false;
        }
        self.current_channel_id = channel_id;
        if self.delta_recording {
            self.pending_delta.current_channel_id = Some(channel_id);
        }
        true
    }

    pub fn get_current_channel_id(&self) -> u32 {
        self.current_channel_id
    }

    pub fn get_listening_channel_id(&self) -> &HashSet<u32> {
        &self.listening_channel_id
    }

    pub fn listen_channel(&mut self, channel_id: u32) -> bool {
        let changed = self.listening_channel_id.insert(channel_id);
        if changed && self.delta_recording {
            let removes = self
                .pending_delta
                .listening_channel_remove
                .get_or_insert_with(HashSet::new);
            removes.remove(&channel_id);
            if removes.is_empty() {
                self.pending_delta.listening_channel_remove = None;
            }

            let adds = self
                .pending_delta
                .listening_channel_add
                .get_or_insert_with(HashSet::new);
            adds.insert(channel_id);
        }
        changed
    }

    pub fn unlisten_channel(&mut self, channel_id: u32) -> bool {
        let changed = self.listening_channel_id.remove(&channel_id);
        if changed && self.delta_recording {
            let adds = self
                .pending_delta
                .listening_channel_add
                .get_or_insert_with(HashSet::new);
            adds.remove(&channel_id);
            if adds.is_empty() {
                self.pending_delta.listening_channel_add = None;
            }

            let removes = self
                .pending_delta
                .listening_channel_remove
                .get_or_insert_with(HashSet::new);
            removes.insert(channel_id);
        }
        changed
    }

    pub fn is_listening_channel(&self, channel_id: u32) -> bool {
        self.listening_channel_id.contains(&channel_id)
    }

    pub fn get_texture_url(&self) -> Option<&str> {
        self.texture_url.as_deref()
    }

    pub fn get_texture_hash(&self) -> Option<&str> {
        self.texture_hash.as_deref()
    }

    pub fn set_texture_blob(&mut self, url: Option<String>, hash: Option<String>) {
        if self.texture_url == url && self.texture_hash == hash {
            return;
        }
        let old_url = self.texture_url.clone();
        let old_hash = self.texture_hash.clone();
        self.texture_url = url;
        self.texture_hash = hash;
        if self.delta_recording {
            if self.texture_url != old_url {
                self.pending_delta.texture_url = Some(self.texture_url.clone());
            }
            if self.texture_hash != old_hash {
                self.pending_delta.texture_hash = Some(self.texture_hash.clone());
            }
        }
    }

    pub fn clear_texture_blob(&mut self) {
        self.set_texture_blob(None, None);
    }

    pub fn get_comment_url(&self) -> Option<&str> {
        self.comment_url.as_deref()
    }

    pub fn get_comment_hash(&self) -> Option<&str> {
        self.comment_hash.as_deref()
    }

    pub fn set_comment_blob(&mut self, url: Option<String>, hash: Option<String>) {
        if self.comment_url == url && self.comment_hash == hash {
            return;
        }
        let old_url = self.comment_url.clone();
        let old_hash = self.comment_hash.clone();
        self.comment_url = url;
        self.comment_hash = hash;
        if self.delta_recording {
            if self.comment_url != old_url {
                self.pending_delta.comment_url = Some(self.comment_url.clone());
            }
            if self.comment_hash != old_hash {
                self.pending_delta.comment_hash = Some(self.comment_hash.clone());
            }
        }
    }

    pub fn clear_comment_blob(&mut self) {
        self.set_comment_blob(None, None);
    }

    // ── Voice / moderation getters & setters ─────────────────────────────

    pub fn is_muted(&self) -> bool {
        self.mute
    }
    pub fn set_mute(&mut self, v: bool) {
        if self.mute == v {
            return;
        }
        self.mute = v;
        if self.delta_recording {
            self.pending_delta.mute = Some(v);
        }
    }

    pub fn is_deafened(&self) -> bool {
        self.deaf
    }
    pub fn set_deaf(&mut self, v: bool) {
        if self.deaf == v {
            return;
        }
        self.deaf = v;
        if self.delta_recording {
            self.pending_delta.deaf = Some(v);
        }
    }

    pub fn is_suppressed(&self) -> bool {
        self.suppress
    }
    pub fn set_suppress(&mut self, v: bool) {
        if self.suppress == v {
            return;
        }
        self.suppress = v;
        if self.delta_recording {
            self.pending_delta.suppress = Some(v);
        }
    }

    pub fn is_self_muted(&self) -> bool {
        self.self_mute
    }
    pub fn set_self_mute(&mut self, v: bool) {
        if self.self_mute == v {
            return;
        }
        self.self_mute = v;
        if self.delta_recording {
            self.pending_delta.self_mute = Some(v);
        }
    }

    pub fn is_self_deafened(&self) -> bool {
        self.self_deaf
    }
    pub fn set_self_deaf(&mut self, v: bool) {
        if self.self_deaf == v {
            return;
        }
        self.self_deaf = v;
        if self.delta_recording {
            self.pending_delta.self_deaf = Some(v);
        }
    }

    pub fn is_priority_speaker(&self) -> bool {
        self.priority_speaker
    }
    pub fn set_priority_speaker(&mut self, v: bool) {
        if self.priority_speaker == v {
            return;
        }
        self.priority_speaker = v;
        if self.delta_recording {
            self.pending_delta.priority_speaker = Some(v);
        }
    }

    pub fn is_recording(&self) -> bool {
        self.recording
    }
    pub fn set_recording(&mut self, v: bool) {
        if self.recording == v {
            return;
        }
        self.recording = v;
        if self.delta_recording {
            self.pending_delta.recording = Some(v);
        }
    }

    pub fn get_plugin_context(&self) -> &[u8] {
        &self.plugin_context
    }
    pub fn set_plugin_context(&mut self, ctx: Bytes) {
        if self.plugin_context == ctx {
            return;
        }
        self.plugin_context = ctx;
        if self.delta_recording {
            self.pending_delta.plugin_context = Some(self.plugin_context.clone());
        }
    }

    pub fn get_plugin_identity(&self) -> &str {
        &self.plugin_identity
    }
    pub fn set_plugin_identity(&mut self, id: String) {
        if self.plugin_identity == id {
            return;
        }
        self.plugin_identity = id;
        if self.delta_recording {
            self.pending_delta.plugin_identity = Some(self.plugin_identity.clone());
        }
    }

    // ── User identity getters & setters ──────────────────────────────────

    pub fn get_user_id(&self) -> Option<u32> {
        self.user_id
    }

    pub fn get_acl_generation(&self) -> u64 {
        self.acl_generation
    }

    fn bump_acl_generation(&mut self) {
        self.acl_generation = self.acl_generation.wrapping_add(1);
    }

    pub fn set_user_id(&mut self, user_id: Option<u32>) {
        if self.user_id == user_id {
            return;
        }
        self.user_id = user_id;
        self.bump_acl_generation();
        if self.delta_recording {
            self.pending_delta.user_id = Some(user_id);
        }
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

    pub fn is_superuser(&self) -> bool {
        self.is_superuser
    }

    pub fn set_superuser(&mut self, value: bool) {
        if self.is_superuser == value {
            return;
        }
        self.is_superuser = value;
        self.bump_acl_generation();
        if self.delta_recording {
            self.pending_delta.is_superuser = Some(value);
        }
    }

    pub fn add_group(&mut self, group: String) {
        if self.groups.insert(group) {
            self.bump_acl_generation();
            if self.delta_recording {
                self.pending_delta.groups = Some(self.groups.clone());
            }
        }
    }

    pub fn del_group(&mut self, group: &str) {
        if self.groups.remove(&group.to_string()) {
            self.bump_acl_generation();
            if self.delta_recording {
                self.pending_delta.groups = Some(self.groups.clone());
            }
        }
    }

    pub fn set_groups(&mut self, groups: HashSet<String>) {
        if self.groups == groups {
            return;
        }
        self.groups = groups;
        self.bump_acl_generation();
        if self.delta_recording {
            self.pending_delta.groups = Some(self.groups.clone());
        }
    }

    pub fn get_tokens(&self) -> &HashSet<String> {
        &self.tokens
    }

    pub fn add_token(&mut self, token: String) {
        if self.tokens.insert(token.to_ascii_lowercase()) {
            self.bump_acl_generation();
            if self.delta_recording {
                self.pending_delta.tokens = Some(self.tokens.clone());
            }
        }
    }

    pub fn del_token(&mut self, token: &str) {
        if self.tokens.remove(&token.to_ascii_lowercase()) {
            self.bump_acl_generation();
            if self.delta_recording {
                self.pending_delta.tokens = Some(self.tokens.clone());
            }
        }
    }

    pub fn set_tokens(&mut self, tokens: HashSet<String>) {
        let tokens = tokens
            .into_iter()
            .map(|token| token.to_ascii_lowercase())
            .collect();

        if self.tokens == tokens {
            return;
        }
        self.tokens = tokens;
        self.bump_acl_generation();
        if self.delta_recording {
            self.pending_delta.tokens = Some(self.tokens.clone());
        }
    }

    pub fn has_token(&self, token: &str) -> bool {
        self.tokens.contains(&token.to_ascii_lowercase())
    }

    pub fn get_display_name(&self) -> &str {
        self.display_name
            .as_deref()
            .expect("Unexpected empty username; Accessing before initialization?")
    }

    pub fn get_display_name_opt(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn set_display_name(&mut self, display_name: Option<String>) {
        if self.display_name == display_name {
            return;
        }
        self.display_name = display_name;
        if self.delta_recording {
            self.pending_delta.display_name = Some(self.display_name.clone());
        }
    }
}

impl Default for ClientGlobalState {
    fn default() -> Self {
        Self::new()
    }
}
