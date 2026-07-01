use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use scc::{Equivalent, HashCache};

const RESOLVED_CHANNEL_CACHE_MAX_CAPACITY: usize = 256;

#[derive(Debug, Clone)]
pub struct VoiceTarget {
    sessions: Vec<u32>,
    channels: Vec<VoiceTargetChannel>,
    resolved_channels:
        Arc<HashCache<ResolvedVoiceTargetChannelCacheKey, Arc<[ResolvedVoiceTargetChannel]>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResolvedVoiceTargetChannelCacheKey {
    server_id: String,
    channel_version: u64,
    source_channel: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct ResolvedVoiceTargetChannelCacheLookupKey<'a> {
    server_id: &'a str,
    channel_version: u64,
    source_channel: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct ResolvedVoiceTargetChannel {
    id: u32,
    group: String,
    current_channel_talk: bool,
    channel_ids: Arc<[u32]>,
    channel_id_set: Arc<HashSet<u32>>,
}

impl ResolvedVoiceTargetChannel {
    pub fn new(id: u32, group: String, current_channel_talk: bool, channel_ids: Vec<u32>) -> Self {
        let channel_id_set = channel_ids.iter().copied().collect();
        Self {
            id,
            group,
            current_channel_talk,
            channel_ids: Arc::from(channel_ids),
            channel_id_set: Arc::new(channel_id_set),
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn group(&self) -> &str {
        &self.group
    }

    pub fn current_channel_talk(&self) -> bool {
        self.current_channel_talk
    }

    pub fn channel_ids(&self) -> &[u32] {
        &self.channel_ids
    }

    pub fn contains_channel(&self, channel_id: u32) -> bool {
        self.channel_id_set.contains(&channel_id)
    }
}

impl Default for VoiceTarget {
    fn default() -> Self {
        Self {
            sessions: Vec::new(),
            channels: Vec::new(),
            resolved_channels: Arc::new(HashCache::with_capacity(
                0,
                RESOLVED_CHANNEL_CACHE_MAX_CAPACITY,
            )),
        }
    }
}

impl VoiceTarget {
    pub fn new() -> Self {
        Self::default()
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

    pub fn cached_resolved_channels(
        &self,
        server_id: &str,
        channel_version: u64,
        source_channel: u32,
    ) -> Option<Arc<[ResolvedVoiceTargetChannel]>> {
        self.resolved_channels.read_sync(
            &ResolvedVoiceTargetChannelCacheLookupKey {
                server_id,
                channel_version,
                source_channel,
            },
            |_, channels| channels.clone(),
        )
    }

    pub fn store_resolved_channels(
        &self,
        server_id: &str,
        channel_version: u64,
        source_channel: u32,
        channels: Arc<[ResolvedVoiceTargetChannel]>,
    ) {
        self.resolved_channels
            .entry_sync(ResolvedVoiceTargetChannelCacheKey::new(
                server_id,
                channel_version,
                source_channel,
            ))
            .put_entry(channels);
    }

    pub fn clear(&mut self) {
        self.sessions.clear();
        self.channels.clear();
        self.resolved_channels.clear_sync();
    }
}

impl ResolvedVoiceTargetChannelCacheKey {
    fn new(server_id: &str, channel_version: u64, source_channel: u32) -> Self {
        Self {
            server_id: server_id.to_owned(),
            channel_version,
            source_channel,
        }
    }
}

impl Equivalent<ResolvedVoiceTargetChannelCacheKey>
    for ResolvedVoiceTargetChannelCacheLookupKey<'_>
{
    fn equivalent(&self, key: &ResolvedVoiceTargetChannelCacheKey) -> bool {
        self.server_id == key.server_id
            && self.channel_version == key.channel_version
            && self.source_channel == key.source_channel
    }
}

impl Hash for ResolvedVoiceTargetChannelCacheLookupKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.server_id.hash(state);
        self.channel_version.hash(state);
        self.source_channel.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_target_cache_is_scoped_by_channel_version() {
        let target = VoiceTarget::new();
        let channels: Arc<[ResolvedVoiceTargetChannel]> =
            Arc::from([ResolvedVoiceTargetChannel::new(
                10,
                String::new(),
                false,
                vec![10],
            )]);

        target.store_resolved_channels("default", 1, 10, channels.clone());

        assert!(target.cached_resolved_channels("default", 1, 10).is_some());
        assert!(target.cached_resolved_channels("default", 2, 10).is_none());
        assert!(target.cached_resolved_channels("default", 1, 10).is_some());
    }

    #[test]
    fn voice_target_cache_clear_removes_cached_entries() {
        let mut target = VoiceTarget::new();
        let channels: Arc<[ResolvedVoiceTargetChannel]> =
            Arc::from([ResolvedVoiceTargetChannel::new(
                10,
                String::new(),
                false,
                vec![10],
            )]);

        target.store_resolved_channels("default", 2, 10, channels);

        assert!(target.cached_resolved_channels("default", 2, 10).is_some());
        target.clear();
        assert!(target.cached_resolved_channels("default", 2, 10).is_none());
    }

    #[test]
    fn voice_target_cache_has_bounded_capacity() {
        let target = VoiceTarget::new();

        assert_eq!(
            *target.resolved_channels.capacity_range().end(),
            RESOLVED_CHANNEL_CACHE_MAX_CAPACITY.next_power_of_two()
        );
    }
}
