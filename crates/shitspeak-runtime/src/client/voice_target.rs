use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;

use super::{ClientInstanceId, client_session_identifier::ClientSessionIdentifier};
use shitspeak_messages::messages::encoder::AudioContext;

#[derive(Debug, Clone)]
pub struct VoiceTarget {
    sessions: Vec<u32>,
    channels: Vec<VoiceTargetChannel>,
    resolved_channels: Arc<
        RwLock<
            Option<(
                ResolvedVoiceTargetChannelCacheKey,
                Arc<[ResolvedVoiceTargetChannel]>,
            )>,
        >,
    >,
    authorized_channels:
        Arc<RwLock<Option<(AuthorizedVoiceTargetChannelCacheKey, AuthorizedVoiceTarget)>>>,
    resolved_recipients: Arc<
        RwLock<
            Option<(
                ResolvedVoiceTargetRecipientsCacheKey,
                Arc<[ResolvedVoiceTargetRecipient]>,
            )>,
        >,
    >,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResolvedVoiceTargetRecipientsCacheKey {
    server_id: String,
    channel_version: u64,
    channel_acl_generation: u64,
    client_version: u64,
    sender_acl_generation: u64,
    hide_users_without_traverse: bool,
    source_channel: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct ResolvedVoiceTargetRecipientsCacheLookupKey<'a> {
    server_id: &'a str,
    channel_version: u64,
    channel_acl_generation: u64,
    client_version: u64,
    sender_acl_generation: u64,
    hide_users_without_traverse: bool,
    source_channel: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizedVoiceTargetChannelCacheKey {
    server_id: String,
    channel_version: u64,
    channel_acl_generation: u64,
    sender_acl_generation: u64,
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
    whole_server: bool,
    authorized: bool,
    channel_ids: Arc<[u32]>,
    channel_id_set: Arc<HashSet<u32>>,
}

#[derive(Debug, Clone)]
pub struct AuthorizedVoiceTarget {
    channels: Arc<[ResolvedVoiceTargetChannel]>,
    s2s_channel_ids: Option<Arc<[u32]>>,
    has_authorized_target: bool,
}

impl AuthorizedVoiceTarget {
    pub fn new(
        channels: Arc<[ResolvedVoiceTargetChannel]>,
        s2s_channel_ids: Option<Arc<[u32]>>,
        has_authorized_target: bool,
    ) -> Self {
        Self {
            channels,
            s2s_channel_ids,
            has_authorized_target,
        }
    }

    pub fn channels(&self) -> &[ResolvedVoiceTargetChannel] {
        &self.channels
    }

    pub fn s2s_channel_ids(&self) -> Option<Arc<[u32]>> {
        self.s2s_channel_ids.clone()
    }

    pub fn has_authorized_target(&self) -> bool {
        self.has_authorized_target
    }
}

impl ResolvedVoiceTargetChannel {
    pub fn new(id: u32, group: String, current_channel_talk: bool, channel_ids: Vec<u32>) -> Self {
        let channel_id_set = channel_ids.iter().copied().collect();
        Self {
            id,
            group,
            current_channel_talk,
            whole_server: false,
            authorized: true,
            channel_ids: Arc::from(channel_ids),
            channel_id_set: Arc::new(channel_id_set),
        }
    }

    pub fn whole_server(group: String) -> Self {
        Self {
            id: 0,
            group,
            current_channel_talk: false,
            whole_server: true,
            authorized: true,
            channel_ids: Arc::from([]),
            channel_id_set: Arc::new(HashSet::new()),
        }
    }

    pub fn denied_like(channel: &Self) -> Self {
        Self {
            id: channel.id,
            group: channel.group.clone(),
            current_channel_talk: channel.current_channel_talk,
            whole_server: channel.whole_server,
            authorized: false,
            channel_ids: Arc::from([]),
            channel_id_set: Arc::new(HashSet::new()),
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

    pub fn is_whole_server(&self) -> bool {
        self.whole_server
    }

    pub fn is_authorized(&self) -> bool {
        self.authorized
    }

    pub fn channel_ids(&self) -> &[u32] {
        &self.channel_ids
    }

    pub fn contains_channel(&self, channel_id: u32) -> bool {
        self.channel_id_set.contains(&channel_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedVoiceTargetRecipient {
    session_id: ClientSessionIdentifier,
    client_instance_id: ClientInstanceId,
    context: AudioContext,
}

impl ResolvedVoiceTargetRecipient {
    pub fn new(
        session_id: ClientSessionIdentifier,
        client_instance_id: ClientInstanceId,
        context: AudioContext,
    ) -> Self {
        Self {
            session_id,
            client_instance_id,
            context,
        }
    }

    pub fn session_id(&self) -> ClientSessionIdentifier {
        self.session_id
    }

    pub fn client_instance_id(&self) -> ClientInstanceId {
        self.client_instance_id
    }

    pub fn context(&self) -> AudioContext {
        self.context
    }
}

impl Default for VoiceTarget {
    fn default() -> Self {
        Self {
            sessions: Vec::new(),
            channels: Vec::new(),
            resolved_channels: Arc::new(RwLock::new(None)),
            authorized_channels: Arc::new(RwLock::new(None)),
            resolved_recipients: Arc::new(RwLock::new(None)),
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
        let lookup = ResolvedVoiceTargetChannelCacheLookupKey {
            server_id,
            channel_version,
            source_channel,
        };
        self.resolved_channels
            .read()
            .as_ref()
            .filter(|(key, _)| lookup.matches(key))
            .map(|(_, channels)| channels.clone())
    }

    pub fn store_resolved_channels(
        &self,
        server_id: &str,
        channel_version: u64,
        source_channel: u32,
        channels: Arc<[ResolvedVoiceTargetChannel]>,
    ) {
        *self.resolved_channels.write() = Some((
            ResolvedVoiceTargetChannelCacheKey::new(server_id, channel_version, source_channel),
            channels,
        ));
    }

    pub fn cached_authorized_target(
        &self,
        server_id: &str,
        channel_version: u64,
        channel_acl_generation: u64,
        sender_acl_generation: u64,
        source_channel: u32,
    ) -> Option<AuthorizedVoiceTarget> {
        self.authorized_channels
            .read()
            .as_ref()
            .filter(|(key, _)| {
                key.server_id == server_id
                    && key.channel_version == channel_version
                    && key.channel_acl_generation == channel_acl_generation
                    && key.sender_acl_generation == sender_acl_generation
                    && key.source_channel == source_channel
            })
            .map(|(_, target)| target.clone())
    }

    pub fn store_authorized_target(
        &self,
        server_id: &str,
        channel_version: u64,
        channel_acl_generation: u64,
        sender_acl_generation: u64,
        source_channel: u32,
        target: AuthorizedVoiceTarget,
    ) {
        *self.authorized_channels.write() = Some((
            AuthorizedVoiceTargetChannelCacheKey {
                server_id: server_id.to_owned(),
                channel_version,
                channel_acl_generation,
                sender_acl_generation,
                source_channel,
            },
            target,
        ));
    }

    pub fn cached_resolved_recipients(
        &self,
        server_id: &str,
        channel_version: u64,
        channel_acl_generation: u64,
        client_version: u64,
        sender_acl_generation: u64,
        hide_users_without_traverse: bool,
        source_channel: u32,
    ) -> Option<Arc<[ResolvedVoiceTargetRecipient]>> {
        let lookup = ResolvedVoiceTargetRecipientsCacheLookupKey {
            server_id,
            channel_version,
            channel_acl_generation,
            client_version,
            sender_acl_generation,
            hide_users_without_traverse,
            source_channel,
        };
        self.resolved_recipients
            .read()
            .as_ref()
            .filter(|(key, _)| lookup.matches(key))
            .map(|(_, recipients)| recipients.clone())
    }

    pub fn store_resolved_recipients(
        &self,
        server_id: &str,
        channel_version: u64,
        channel_acl_generation: u64,
        client_version: u64,
        sender_acl_generation: u64,
        hide_users_without_traverse: bool,
        source_channel: u32,
        recipients: Arc<[ResolvedVoiceTargetRecipient]>,
    ) {
        *self.resolved_recipients.write() = Some((
            ResolvedVoiceTargetRecipientsCacheKey::new(
                server_id,
                channel_version,
                channel_acl_generation,
                client_version,
                sender_acl_generation,
                hide_users_without_traverse,
                source_channel,
            ),
            recipients,
        ));
    }

    pub fn clear(&mut self) {
        self.sessions.clear();
        self.channels.clear();
        *self.resolved_channels.write() = None;
        *self.authorized_channels.write() = None;
        *self.resolved_recipients.write() = None;
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

impl ResolvedVoiceTargetRecipientsCacheKey {
    fn new(
        server_id: &str,
        channel_version: u64,
        channel_acl_generation: u64,
        client_version: u64,
        sender_acl_generation: u64,
        hide_users_without_traverse: bool,
        source_channel: u32,
    ) -> Self {
        Self {
            server_id: server_id.to_owned(),
            channel_version,
            channel_acl_generation,
            client_version,
            sender_acl_generation,
            hide_users_without_traverse,
            source_channel,
        }
    }
}

impl ResolvedVoiceTargetChannelCacheLookupKey<'_> {
    fn matches(&self, key: &ResolvedVoiceTargetChannelCacheKey) -> bool {
        self.server_id == key.server_id
            && self.channel_version == key.channel_version
            && self.source_channel == key.source_channel
    }
}

impl ResolvedVoiceTargetRecipientsCacheLookupKey<'_> {
    fn matches(&self, key: &ResolvedVoiceTargetRecipientsCacheKey) -> bool {
        self.server_id == key.server_id
            && self.channel_version == key.channel_version
            && self.channel_acl_generation == key.channel_acl_generation
            && self.client_version == key.client_version
            && self.sender_acl_generation == key.sender_acl_generation
            && self.hide_users_without_traverse == key.hide_users_without_traverse
            && self.source_channel == key.source_channel
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
    fn voice_target_recipient_cache_is_scoped_by_versions() {
        let target = VoiceTarget::new();
        let recipients: Arc<[ResolvedVoiceTargetRecipient]> =
            Arc::from([ResolvedVoiceTargetRecipient::new(
                ClientSessionIdentifier::from(5),
                99,
                AudioContext::Shout,
            )]);

        target.store_resolved_recipients("default", 1, 2, 3, 4, false, 10, recipients.clone());

        assert!(
            target
                .cached_resolved_recipients("default", 1, 2, 3, 4, false, 10)
                .is_some()
        );
        assert!(
            target
                .cached_resolved_recipients("default", 2, 2, 3, 4, false, 10)
                .is_none()
        );
        assert!(
            target
                .cached_resolved_recipients("default", 1, 3, 3, 4, false, 10)
                .is_none()
        );
        assert!(
            target
                .cached_resolved_recipients("default", 1, 2, 4, 4, false, 10)
                .is_none()
        );
        assert!(
            target
                .cached_resolved_recipients("default", 1, 2, 3, 4, true, 10)
                .is_none()
        );
        assert!(
            target
                .cached_resolved_recipients("default", 1, 2, 3, 4, false, 11)
                .is_none()
        );
    }

    #[test]
    fn voice_target_cache_clear_removes_cached_recipients() {
        let mut target = VoiceTarget::new();
        let recipients: Arc<[ResolvedVoiceTargetRecipient]> =
            Arc::from([ResolvedVoiceTargetRecipient::new(
                ClientSessionIdentifier::from(5),
                99,
                AudioContext::Whisper,
            )]);

        target.store_resolved_recipients("default", 1, 2, 3, 4, false, 10, recipients);

        assert!(
            target
                .cached_resolved_recipients("default", 1, 2, 3, 4, false, 10)
                .is_some()
        );
        target.clear();
        assert!(
            target
                .cached_resolved_recipients("default", 1, 2, 3, 4, false, 10)
                .is_none()
        );
    }

    #[test]
    fn voice_target_cache_retains_only_latest_entry() {
        let target = VoiceTarget::new();
        let first: Arc<[ResolvedVoiceTargetChannel]> =
            Arc::from([ResolvedVoiceTargetChannel::new(
                10,
                String::new(),
                false,
                vec![10],
            )]);
        let second: Arc<[ResolvedVoiceTargetChannel]> =
            Arc::from([ResolvedVoiceTargetChannel::new(
                20,
                String::new(),
                false,
                vec![20],
            )]);

        target.store_resolved_channels("default", 1, 10, first);
        target.store_resolved_channels("default", 2, 20, second);

        assert!(target.cached_resolved_channels("default", 1, 10).is_none());
        assert!(target.cached_resolved_channels("default", 2, 20).is_some());
    }
}
