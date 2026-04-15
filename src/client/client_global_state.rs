use std::collections::HashSet;

use crate::protocol_version::ProtocolVersion;

pub struct ClientGlobalState {
    protocol_version: Option<ProtocolVersion>, 
    release: Option<String>,
    os: Option<String>,
    os_version: Option<String>,

    current_channel_id: u32,
    last_active_timestamp: Option<std::time::Instant>,
    listening_channel_id: HashSet<u32>,


    // ── Texture blob ───────────────────────────────────────────────────────
    /// URL supplied by the auth server at login; propagated over S2S.
    texture_url: Option<String>,
    /// SHA-1 hex of the texture blob in `SessionBlobStore`; also propagated
    /// over S2S so peer nodes can check their local cache.
    texture_hash: Option<String>,

    // ── Comment blob ───────────────────────────────────────────────────────
    /// URL supplied by the auth server at login; propagated over S2S.
    comment_url: Option<String>,
    /// SHA-1 hex of the comment blob in `SessionBlobStore`.
    comment_hash: Option<String>,
}

impl ClientGlobalState {
    pub fn new() -> Self {
        ClientGlobalState {
            protocol_version: None,
            release: None,
            os: None,
            os_version: None,

            current_channel_id: 0,
            last_active_timestamp: None,
            listening_channel_id: HashSet::new(),

            texture_url: None,
            texture_hash: None,
            comment_url: None,
            comment_hash: None,
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
}

impl Default for ClientGlobalState {
    fn default() -> Self {
        Self::new()
    }
}
