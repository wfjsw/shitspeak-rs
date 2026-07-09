//! Voice routing logic — determines recipients and dispatches audio packets.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use scc::HashCache;
use tracing::Instrument;

use super::codec::{self, Audio, PacketFormat};
use super::metrics::{
    VoiceAgeStage, VoiceDispatchMode, VoiceEgressResult, VoiceEgressTransport, VoicePipelinePath,
    VoicePipelineStage, VoiceRouteKind, VoiceRouteSource, VoiceSchedulerStage, VoiceUdpSendResult,
};
use super::routing_queue::VoiceRoutingPayload;
use super::udp_batch::{self, DatagramBatch};
use crate::{
    client::{
        Client, ClientInstanceId,
        client_session_identifier::ClientSessionIdentifier,
        crypt::CryptState,
        voice_target::{ResolvedVoiceTargetChannel, ResolvedVoiceTargetRecipient, VoiceTarget},
    },
    constants::PROTOBUF_INTRODUCED_VERSION,
    messages::encoder::{Audio as AudioWire, AudioContext, AudioHeader, AudioTarget},
    server::Server,
};
use shitspeak_s2s::application::proto::{
    VoiceFrame, VoiceIntent, VoiceIntentKind, VoiceIntentNormal, VoiceIntentTarget,
    VoiceTargetChannel as S2SVoiceTargetChannel,
};

/// Recipient count above which the encrypt fan-out is dispatched to rayon
/// inside `spawn_blocking`. Below this threshold, sequential per-recipient
/// encrypt on the routing task is faster: the per-recipient unit of work
/// (~450 ns at 170-byte packet) is too small to amortize rayon's task
/// scheduling overhead. Fresh profiling shows sequential remains faster at
/// 256 recipients; rayon starts paying off around 512.
const RAYON_FANOUT_THRESHOLD: usize = 512;
const RAYON_FANOUT_BATCH_MIN_LEN: usize = 256;
const S2S_RECIPIENT_CACHE_INITIAL_CAPACITY: usize = 256;
const S2S_RECIPIENT_CACHE_MAX_CAPACITY: usize = 65536;

static S2S_TARGET_RECIPIENT_CACHE: LazyLock<
    AdaptiveHashCache<S2SVoiceTargetResolutionCacheKey, Arc<[ResolvedVoiceTargetRecipient]>>,
> = LazyLock::new(|| {
    AdaptiveHashCache::new(
        S2S_RECIPIENT_CACHE_INITIAL_CAPACITY,
        S2S_RECIPIENT_CACHE_MAX_CAPACITY,
    )
});

static S2S_NORMAL_RECIPIENT_CACHE: LazyLock<
    AdaptiveHashCache<S2SVoiceNormalResolutionCacheKey, Arc<[ResolvedVoiceTargetRecipient]>>,
> = LazyLock::new(|| {
    AdaptiveHashCache::new(
        S2S_RECIPIENT_CACHE_INITIAL_CAPACITY,
        S2S_RECIPIENT_CACHE_MAX_CAPACITY,
    )
});

struct AdaptiveHashCache<K, V> {
    state: RwLock<AdaptiveHashCacheState<K, V>>,
    max_capacity: usize,
}

struct AdaptiveHashCacheState<K, V> {
    cache: Arc<HashCache<K, V>>,
    current_max_capacity: usize,
}

impl<K, V> AdaptiveHashCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    fn new(initial_capacity: usize, max_capacity: usize) -> Self {
        let initial_capacity = adaptive_cache_capacity(initial_capacity, max_capacity);
        Self {
            state: RwLock::new(AdaptiveHashCacheState {
                cache: Arc::new(HashCache::with_capacity(0, initial_capacity)),
                current_max_capacity: initial_capacity,
            }),
            max_capacity: adaptive_cache_capacity(max_capacity, max_capacity),
        }
    }

    fn read<R, F: FnOnce(&K, &V) -> R>(&self, key: &K, reader: F) -> Option<R> {
        let cache = self.cache();
        cache.read_sync(key, reader)
    }

    fn put(&self, key: K, value: V) {
        let mut state = self.state.write();
        if state.current_max_capacity < self.max_capacity
            && state.cache.len().saturating_mul(4) >= state.current_max_capacity.saturating_mul(3)
        {
            let next_capacity = state
                .current_max_capacity
                .saturating_mul(2)
                .min(self.max_capacity);
            let next_cache = Arc::new(HashCache::with_capacity(0, next_capacity));
            state.cache.iter_sync(|key, value| {
                next_cache.entry_sync(key.clone()).put_entry(value.clone());
                true
            });
            *state = AdaptiveHashCacheState {
                cache: next_cache,
                current_max_capacity: next_capacity,
            };
        }
        state.cache.entry_sync(key).put_entry(value);
    }

    fn cache(&self) -> Arc<HashCache<K, V>> {
        self.state.read().cache.clone()
    }

    fn current_max_capacity(&self) -> usize {
        self.state.read().current_max_capacity
    }
}

fn adaptive_cache_capacity(requested_capacity: usize, max_capacity: usize) -> usize {
    requested_capacity
        .max(64)
        .min(max_capacity.max(64))
        .next_power_of_two()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct S2SVoiceTargetResolutionCacheKey {
    server_identity: usize,
    local_node_id: u16,
    server_id: String,
    sender_session: ClientSessionIdentifier,
    sender_instance_id: Option<ClientInstanceId>,
    channel_version: u64,
    channel_acl_generation: u64,
    client_version: u64,
    hide_users_without_traverse: bool,
    source_channel: u32,
    sessions: Vec<u32>,
    channels: Vec<S2SVoiceTargetChannelCacheKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct S2SVoiceNormalResolutionCacheKey {
    server_identity: usize,
    local_node_id: u16,
    server_id: String,
    sender_session: ClientSessionIdentifier,
    sender_instance_id: Option<ClientInstanceId>,
    channel_version: u64,
    channel_acl_generation: u64,
    client_version: u64,
    hide_users_without_traverse: bool,
    source_channel: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct S2SVoiceTargetChannelCacheKey {
    id: u32,
    children: bool,
    links: bool,
    group: String,
}

/// Pluck the recipient's preferred wire format. Lock-free read backed by
/// the per-client `AtomicU64` protocol version on `Client`.
///
/// Protobuf encoding is only used when the server itself declares a
/// protocol version >= 1.5.0 (`PROTOBUF_INTRODUCED_VERSION`). If the
/// server is running in legacy mode (`server_protocol_version < 1.5.0`), all
/// outbound voice is encoded as legacy regardless of what the client
/// declares.
#[inline]
fn client_packet_format(
    client: &Client,
    server_protocol_version: crate::protocol_version::ProtocolVersion,
) -> PacketFormat {
    if server_protocol_version >= PROTOBUF_INTRODUCED_VERSION && client.uses_protobuf() {
        PacketFormat::Protobuf
    } else {
        PacketFormat::Legacy
    }
}

fn encode_s2s_voice_payload(audio: &Audio) -> Bytes {
    match &audio.audio_payload {
        codec::AudioPayload::Opus(opus) => {
            let positional_data = audio
                .positional_data
                .map(|[x, y, z]| vec![x, y, z])
                .unwrap_or_default();
            let wire = AudioWire {
                header: Some(AudioHeader::Target(audio.target)),
                sender_session: 0,
                frame_number: audio.frame_number,
                opus_data: opus.frame.clone(),
                positional_data,
                volume_adjustment: audio.volume_adjustment,
                is_terminator: opus.is_terminator,
            };
            let mut encoded = BytesMut::with_capacity(1 + wire.encoded_len());
            encoded.extend_from_slice(&[0x00]);
            match wire.encode(&mut encoded) {
                Ok(()) => encoded.freeze(),
                Err(_) => Bytes::new(),
            }
        }
        _ => audio.encode(AudioContext::Normal, PacketFormat::Legacy),
    }
}

/// Encoded plaintext + its precomputed OCB2 plaintext-checksum. Pairing the
/// two on the cache lets every recipient sharing the same plaintext skip the
/// per-block XOR-fold inside the encrypt path (saves ~13% of fan-out CPU at
/// 256 recipients on a 175 B packet — see the phase profile in
/// `client::crypt::profile_test`).
#[derive(Clone)]
struct Encoded {
    bytes: Bytes,
    checksum: [u8; 16],
}

/// Per-(format, context) plaintext cache. Inlined fixed-size storage covers
/// every case `route_voice` produces (≤4 unique keys: 2 formats × ≤2 distinct
/// outbound contexts) without allocation. The overflow `Vec` is a defensive
/// fallback should new audio contexts be added.
struct EncodeCache {
    slots: [Option<((PacketFormat, AudioContext), Encoded)>; 4],
    overflow: Vec<((PacketFormat, AudioContext), Encoded)>,
}

impl EncodeCache {
    fn new() -> Self {
        Self {
            slots: [const { None }; 4],
            overflow: Vec::new(),
        }
    }

    fn get_or_encode(
        &mut self,
        audio: &Audio,
        context: AudioContext,
        format: PacketFormat,
    ) -> Encoded {
        let key = (format, context);
        for slot in &self.slots {
            if let Some((k, e)) = slot {
                if *k == key {
                    return e.clone();
                }
            }
        }
        for (k, e) in &self.overflow {
            if *k == key {
                return e.clone();
            }
        }
        let bytes = audio.encode(context, format);
        let checksum = CryptState::compute_plaintext_checksum(&bytes);
        let entry = Encoded { bytes, checksum };
        for slot in &mut self.slots {
            if slot.is_none() {
                *slot = Some((key, entry.clone()));
                return entry;
            }
        }
        self.overflow.push((key, entry.clone()));
        entry
    }
}

const S2S_TARGET_NORMAL: u32 = 0;
const S2S_TARGET_SHOUT: u32 = 1;

fn normal_intent(source_channel: u32) -> VoiceIntent {
    VoiceIntent {
        kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
            source_channel,
        })),
    }
}

fn target_intent(
    source_channel: u32,
    vt: &crate::client::voice_target::VoiceTarget,
) -> VoiceIntent {
    VoiceIntent {
        kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
            source_channel,
            sessions: vt.sessions().to_vec(),
            channels: vt
                .channels()
                .iter()
                .map(|ch| S2SVoiceTargetChannel {
                    id: ch.id(),
                    children: ch.sub_channels(),
                    links: ch.links(),
                    group: ch.only_group().to_owned(),
                })
                .collect(),
        })),
    }
}

fn voice_target_is_current_channel_or_links(vt: &VoiceTarget, source_channel: u32) -> bool {
    if !vt.sessions().is_empty() || vt.channels().len() != 1 {
        return false;
    }

    let channel = &vt.channels()[0];
    channel.id() == source_channel
        && !channel.sub_channels()
        && channel.only_group().trim().is_empty()
}

fn audio_context_from_target_kind(target_kind: u32) -> AudioContext {
    match target_kind {
        1 => AudioContext::Shout,
        2 => AudioContext::Whisper,
        3 => AudioContext::Listen,
        _ => AudioContext::Normal,
    }
}

async fn client_matches_voice_target_group(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    server_id: &str,
    evaluation_channel: u32,
    group: &str,
) -> bool {
    let group = group.trim();
    if group.is_empty() {
        return true;
    }
    let groups: Vec<String> = client.get_groups_clone().into_iter().collect();
    let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();
    let tokens: Vec<String> = client.get_tokens_clone().into_iter().collect();
    let token_refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
    let home_channel_id = client.get_current_channel_id();
    let eval_ancestors: Vec<u32> = server
        .get_channels()
        .get_ancestors_in_server(server_id, evaluation_channel)
        .await
        .into_iter()
        .map(|ancestor| ancestor.id)
        .collect();
    let home_ancestors: Vec<u32> = if home_channel_id == evaluation_channel {
        eval_ancestors.clone()
    } else {
        server
            .get_channels()
            .get_ancestors_in_server(server_id, home_channel_id)
            .await
            .into_iter()
            .map(|ancestor| ancestor.id)
            .collect()
    };
    let evaluation =
        crate::client::group::ChannelHierarchy::new(evaluation_channel, &eval_ancestors);
    let home = crate::client::group::ChannelHierarchy::new(home_channel_id, &home_ancestors);
    let membership = crate::client::group::ClientMembershipQuery::new(
        &group_refs,
        client.get_user_id().is_some(),
        &token_refs,
        client.get_certificate_hash(),
        client.is_verified(),
        Some(client.get_real_ip_address()),
    )
    .with_home_channel(home);
    crate::client::group::is_member_in_group(group, evaluation, Some(evaluation), &[], &membership)
}

fn push_unique_target(
    targets: &mut Vec<(Arc<Box<Client>>, AudioContext)>,
    seen: &mut HashSet<(ClientSessionIdentifier, ClientInstanceId, AudioContext)>,
    sender_id: ClientSessionIdentifier,
    sender_instance_id: Option<ClientInstanceId>,
    client: Arc<Box<Client>>,
    context: AudioContext,
) {
    if client.get_session_id() == sender_id
        && sender_instance_id.is_some_and(|id| id == client.client_instance_id())
    {
        return;
    }
    if !client.is_authenticated() {
        return;
    }
    if !client.read_local_state().is_some() {
        return;
    }
    if !client.can_receive_voice() {
        return;
    }
    if seen.insert((
        client.get_session_id(),
        client.client_instance_id(),
        context,
    )) {
        targets.push((client, context));
    }
}

async fn live_targets_from_cached_recipients(
    server: &Arc<Box<Server>>,
    server_id: &str,
    recipients: &[ResolvedVoiceTargetRecipient],
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    let mut targets = Vec::with_capacity(recipients.len());
    let local_node_id = server.get_clients().local_node_id();
    let session_ids = recipients
        .iter()
        .map(ResolvedVoiceTargetRecipient::session_id)
        .collect::<Vec<_>>();
    let clients = server
        .get_clients()
        .get_local_clients_by_ids_in_server(server_id, &session_ids)
        .await;

    for (recipient, client) in recipients.iter().zip(clients) {
        let session_id = recipient.session_id();
        if session_id.get_node_id() != local_node_id {
            continue;
        }
        let Some(client) = client else {
            continue;
        };
        if client.client_instance_id() != recipient.client_instance_id() {
            continue;
        }
        if !client.is_authenticated() {
            continue;
        }
        if !client.read_local_state().is_some() {
            continue;
        }
        if !client.can_receive_voice() {
            continue;
        }
        targets.push((client, recipient.context()));
    }

    targets
}

fn cacheable_recipients_from_targets(
    targets: &[(Arc<Box<Client>>, AudioContext)],
) -> Arc<[ResolvedVoiceTargetRecipient]> {
    targets
        .iter()
        .map(|(client, context)| {
            ResolvedVoiceTargetRecipient::new(
                client.get_session_id(),
                client.client_instance_id(),
                *context,
            )
        })
        .collect::<Vec<_>>()
        .into()
}

async fn resolve_voice_intent(
    server: &Arc<Box<Server>>,
    sender: Option<&Arc<Box<Client>>>,
    server_id: &str,
    sender_id: ClientSessionIdentifier,
    intent: &VoiceIntent,
    default_context: AudioContext,
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    resolve_voice_intent_with_resolved_channels(
        server,
        sender,
        server_id,
        sender_id,
        intent,
        default_context,
        None,
    )
    .await
}

fn s2s_target_resolution_cache_key(
    server: &Arc<Box<Server>>,
    sender: Option<&Arc<Box<Client>>>,
    server_id: &str,
    sender_id: ClientSessionIdentifier,
    intent: &VoiceIntent,
) -> Option<S2SVoiceTargetResolutionCacheKey> {
    let target = match intent.kind.as_ref()? {
        VoiceIntentKind::Target(target) => target,
        _ => return None,
    };

    Some(S2SVoiceTargetResolutionCacheKey {
        server_identity: Arc::as_ptr(server) as usize,
        local_node_id: server.get_clients().local_node_id(),
        server_id: server_id.to_owned(),
        sender_session: sender_id,
        sender_instance_id: sender.map(|sender| sender.client_instance_id()),
        channel_version: server.get_channels().current_version_in_server(server_id),
        channel_acl_generation: server.get_channels().channel_acl_generation(),
        client_version: server.get_clients().current_version_in_server(server_id),
        hide_users_without_traverse: server.get_hide_users_without_traverse(),
        source_channel: target.source_channel,
        sessions: target.sessions.clone(),
        channels: target
            .channels
            .iter()
            .map(|channel| S2SVoiceTargetChannelCacheKey {
                id: channel.id,
                children: channel.children,
                links: channel.links,
                group: channel.group.clone(),
            })
            .collect(),
    })
}

fn s2s_normal_resolution_cache_key(
    server: &Arc<Box<Server>>,
    sender: Option<&Arc<Box<Client>>>,
    server_id: &str,
    sender_id: ClientSessionIdentifier,
    intent: &VoiceIntent,
) -> Option<S2SVoiceNormalResolutionCacheKey> {
    let sender = sender?;
    let normal = match intent.kind.as_ref()? {
        VoiceIntentKind::Normal(normal) => normal,
        _ => return None,
    };

    Some(S2SVoiceNormalResolutionCacheKey {
        server_identity: Arc::as_ptr(server) as usize,
        local_node_id: server.get_clients().local_node_id(),
        server_id: server_id.to_owned(),
        sender_session: sender_id,
        sender_instance_id: Some(sender.client_instance_id()),
        channel_version: server.get_channels().current_version_in_server(server_id),
        channel_acl_generation: server.get_channels().channel_acl_generation(),
        client_version: server.get_clients().current_version_in_server(server_id),
        hide_users_without_traverse: server.get_hide_users_without_traverse(),
        source_channel: normal.source_channel,
    })
}

async fn resolve_s2s_voice_intent(
    server: &Arc<Box<Server>>,
    sender: Option<&Arc<Box<Client>>>,
    server_id: &str,
    sender_id: ClientSessionIdentifier,
    intent: &VoiceIntent,
    default_context: AudioContext,
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    if let Some(cache_key) =
        s2s_target_resolution_cache_key(server, sender, server_id, sender_id, intent)
    {
        if let Some(recipients) =
            S2S_TARGET_RECIPIENT_CACHE.read(&cache_key, |_, recipients| recipients.clone())
        {
            return live_targets_from_cached_recipients(server, server_id, &recipients).await;
        }

        let targets = resolve_voice_intent(
            server,
            sender,
            server_id,
            sender_id,
            intent,
            default_context,
        )
        .await;
        S2S_TARGET_RECIPIENT_CACHE.put(cache_key, cacheable_recipients_from_targets(&targets));
        return targets;
    }

    if let Some(cache_key) =
        s2s_normal_resolution_cache_key(server, sender, server_id, sender_id, intent)
    {
        if let Some(recipients) =
            S2S_NORMAL_RECIPIENT_CACHE.read(&cache_key, |_, recipients| recipients.clone())
        {
            return live_targets_from_cached_recipients(server, server_id, &recipients).await;
        }

        let targets = resolve_voice_intent(
            server,
            sender,
            server_id,
            sender_id,
            intent,
            default_context,
        )
        .await;
        S2S_NORMAL_RECIPIENT_CACHE.put(cache_key, cacheable_recipients_from_targets(&targets));
        return targets;
    }

    resolve_voice_intent(
        server,
        sender,
        server_id,
        sender_id,
        intent,
        default_context,
    )
    .await
}

async fn resolve_voice_intent_with_resolved_channels(
    server: &Arc<Box<Server>>,
    sender: Option<&Arc<Box<Client>>>,
    server_id: &str,
    sender_id: ClientSessionIdentifier,
    intent: &VoiceIntent,
    default_context: AudioContext,
    resolved_channels: Option<&[ResolvedVoiceTargetChannel]>,
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let local_node_id = server.get_clients().local_node_id();
    let sender_instance_id = sender.map(|sender| sender.client_instance_id());

    match intent.kind.as_ref() {
        Some(VoiceIntentKind::Normal(normal)) => {
            let source_channel = normal.source_channel;
            let channel_clients = server
                .get_clients()
                .get_local_clients_in_channel_in_server(server_id, source_channel)
                .await;
            for client in channel_clients {
                if let Some(sender) = sender {
                    if !crate::client::visibility::can_view_user(server, &client, sender).await {
                        continue;
                    }
                }
                push_unique_target(
                    &mut targets,
                    &mut seen,
                    sender_id,
                    sender_instance_id,
                    client,
                    AudioContext::Normal,
                );
            }

            if let Some(sender) = sender {
                let linked_ids = server
                    .get_channels()
                    .effective_link_group_in_server(server_id, source_channel);
                for linked_id in linked_ids.iter().flat_map(|group| group.iter()).copied() {
                    if linked_id == source_channel {
                        continue;
                    }
                    let perms = crate::client::acl::compute_permissions_for_client(
                        server, sender, linked_id,
                    )
                    .await;
                    if !perms.contains(crate::acl::ACLPermissions::Speak) {
                        continue;
                    }
                    let linked_clients = server
                        .get_clients()
                        .get_local_clients_in_channel_in_server(server_id, linked_id)
                        .await;
                    for client in linked_clients {
                        if !crate::client::visibility::can_view_user(server, &client, sender).await
                        {
                            continue;
                        }
                        push_unique_target(
                            &mut targets,
                            &mut seen,
                            sender_id,
                            sender_instance_id,
                            client,
                            AudioContext::Normal,
                        );
                    }
                }
            }

            let listeners = server
                .get_clients()
                .get_local_listeners_for_channel_in_server(server_id, source_channel)
                .await;
            for client in listeners {
                if let Some(sender) = sender {
                    if !crate::client::visibility::can_view_user(server, &client, sender).await {
                        continue;
                    }
                }
                push_unique_target(
                    &mut targets,
                    &mut seen,
                    sender_id,
                    sender_instance_id,
                    client,
                    AudioContext::Listen,
                );
            }
        }
        Some(VoiceIntentKind::Target(target)) => {
            for session_raw in &target.sessions {
                let session_id =
                    crate::client::client_session_identifier::ClientSessionIdentifier::from(
                        *session_raw,
                    );
                if session_id.node_id != local_node_id {
                    continue;
                }
                if let Some(client) = server
                    .get_clients()
                    .get_client_in_server(server_id, session_id)
                    .await
                {
                    if let Some(sender) = sender {
                        if !crate::client::visibility::can_view_user(server, sender, &client).await
                        {
                            continue;
                        }
                        if !crate::client::visibility::can_view_user(server, &client, sender).await
                        {
                            continue;
                        }
                        let perms = crate::client::acl::compute_permissions_for_client(
                            server,
                            sender,
                            client.get_current_channel_id(),
                        )
                        .await;
                        if !perms.contains(crate::acl::ACLPermissions::Whisper) {
                            continue;
                        }
                    }
                    push_unique_target(
                        &mut targets,
                        &mut seen,
                        sender_id,
                        sender_instance_id,
                        client,
                        AudioContext::Whisper,
                    );
                }
            }

            for (target_index, ch_target) in target.channels.iter().enumerate() {
                let owned_resolved_channel;
                let resolved_channel = if let Some(resolved_channel) =
                    resolved_channels.and_then(|channels| channels.get(target_index))
                {
                    resolved_channel
                } else {
                    owned_resolved_channel = resolve_voice_target_channel(
                        server,
                        server_id,
                        target.source_channel,
                        ch_target,
                    )
                    .await;
                    &owned_resolved_channel
                };
                let mut channel_ids = resolved_channel.channel_ids().to_vec();

                if let Some(sender) = sender {
                    let mut allowed_channels = Vec::new();
                    let mut allowed_channel_set = HashSet::new();
                    let source_channel = target.source_channel;
                    for channel_id in channel_ids {
                        let perms = crate::client::acl::compute_permissions_for_client(
                            server, sender, channel_id,
                        )
                        .await;
                        let allowed = if resolved_channel.current_channel_talk()
                            && channel_id == source_channel
                        {
                            perms.contains(crate::acl::ACLPermissions::Speak)
                        } else {
                            perms.contains(crate::acl::ACLPermissions::Whisper)
                        };
                        if allowed {
                            if allowed_channel_set.insert(channel_id) {
                                allowed_channels.push(channel_id);
                            }
                        }
                    }
                    channel_ids = allowed_channels;
                    if channel_ids.is_empty() {
                        continue;
                    }

                    let channel_clients = server
                        .get_clients()
                        .get_local_clients_in_channels_in_server(server_id, &channel_ids)
                        .await;
                    for client in channel_clients {
                        let client_channel = client.get_current_channel_id();
                        if !allowed_channel_set.contains(&client_channel) {
                            continue;
                        }
                        if !client_matches_voice_target_group(
                            server,
                            &client,
                            server_id,
                            client_channel,
                            resolved_channel.group(),
                        )
                        .await
                        {
                            continue;
                        }
                        if !crate::client::visibility::can_view_user(server, &client, sender).await
                        {
                            continue;
                        }
                        push_unique_target(
                            &mut targets,
                            &mut seen,
                            sender_id,
                            sender_instance_id,
                            client,
                            AudioContext::Shout,
                        );
                    }

                    for channel_id in &channel_ids {
                        let channel_listeners = server
                            .get_clients()
                            .get_local_listeners_for_channel_in_server(server_id, *channel_id)
                            .await;
                        for client in channel_listeners {
                            if !client_matches_voice_target_group(
                                server,
                                &client,
                                server_id,
                                *channel_id,
                                resolved_channel.group(),
                            )
                            .await
                            {
                                continue;
                            }
                            if !crate::client::visibility::can_view_user(server, &client, sender)
                                .await
                            {
                                continue;
                            }
                            push_unique_target(
                                &mut targets,
                                &mut seen,
                                sender_id,
                                sender_instance_id,
                                client,
                                AudioContext::Listen,
                            );
                        }
                    }
                    continue;
                }
                if channel_ids.is_empty() {
                    continue;
                }

                let channel_clients = server
                    .get_clients()
                    .get_local_clients_in_channels_in_server(server_id, &channel_ids)
                    .await;
                for client in channel_clients {
                    let client_channel = client.get_current_channel_id();
                    if !resolved_channel.contains_channel(client_channel) {
                        continue;
                    }
                    if !client_matches_voice_target_group(
                        server,
                        &client,
                        server_id,
                        client_channel,
                        resolved_channel.group(),
                    )
                    .await
                    {
                        continue;
                    }
                    if let Some(sender) = sender {
                        if !crate::client::visibility::can_view_user(server, &client, sender).await
                        {
                            continue;
                        }
                    }
                    push_unique_target(
                        &mut targets,
                        &mut seen,
                        sender_id,
                        sender_instance_id,
                        client,
                        AudioContext::Shout,
                    );
                }

                for channel_id in &channel_ids {
                    let channel_listeners = server
                        .get_clients()
                        .get_local_listeners_for_channel_in_server(server_id, *channel_id)
                        .await;
                    for client in channel_listeners {
                        if !client_matches_voice_target_group(
                            server,
                            &client,
                            server_id,
                            *channel_id,
                            resolved_channel.group(),
                        )
                        .await
                        {
                            continue;
                        }
                        if let Some(sender) = sender {
                            if !crate::client::visibility::can_view_user(server, &client, sender)
                                .await
                            {
                                continue;
                            }
                        }
                        push_unique_target(
                            &mut targets,
                            &mut seen,
                            sender_id,
                            sender_instance_id,
                            client,
                            AudioContext::Listen,
                        );
                    }
                }
            }
        }
        None => {
            if let Some(sender) = sender {
                push_unique_target(
                    &mut targets,
                    &mut seen,
                    sender_id,
                    sender_instance_id,
                    sender.clone(),
                    default_context,
                );
            }
        }
    }

    targets
}

async fn resolve_voice_target_channel(
    server: &Arc<Box<Server>>,
    server_id: &str,
    source_channel: u32,
    ch_target: &S2SVoiceTargetChannel,
) -> ResolvedVoiceTargetChannel {
    let mut channel_ids = if ch_target.children {
        server
            .get_channels()
            .subtree_ids_in_server(server_id, ch_target.id)
            .await
    } else {
        vec![ch_target.id]
    };
    let mut channel_id_set: HashSet<u32> = channel_ids.iter().copied().collect();

    if ch_target.links {
        let initial_channel_len = channel_ids.len();
        for index in 0..initial_channel_len {
            let ch_id = channel_ids[index];
            if let Some(group) = server
                .get_channels()
                .effective_link_group_in_server(server_id, ch_id)
            {
                for &linked_id in group.iter() {
                    if channel_id_set.insert(linked_id) {
                        channel_ids.push(linked_id);
                    }
                }
            }
        }
    }

    ResolvedVoiceTargetChannel::new(
        ch_target.id,
        ch_target.group.clone(),
        ch_target.id == source_channel
            && !ch_target.children
            && !ch_target.links
            && ch_target.group.trim().is_empty(),
        channel_ids,
    )
}

async fn resolved_voice_target_channels(
    server: &Arc<Box<Server>>,
    server_id: &str,
    source_channel: u32,
    vt: &VoiceTarget,
) -> Arc<[ResolvedVoiceTargetChannel]> {
    let channel_version = server.get_channels().current_version_in_server(server_id);
    if let Some(channels) = vt.cached_resolved_channels(server_id, channel_version, source_channel)
    {
        return channels;
    }

    let mut channels = Vec::with_capacity(vt.channels().len());
    for ch in vt.channels() {
        let target = S2SVoiceTargetChannel {
            id: ch.id(),
            children: ch.sub_channels(),
            links: ch.links(),
            group: ch.only_group().to_owned(),
        };
        channels
            .push(resolve_voice_target_channel(server, server_id, source_channel, &target).await);
    }

    let channels: Arc<[ResolvedVoiceTargetChannel]> = Arc::from(channels);
    vt.store_resolved_channels(server_id, channel_version, source_channel, channels.clone());
    channels
}

async fn resolved_voice_target_recipients(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    server_id: &str,
    sender_id: ClientSessionIdentifier,
    source_channel: u32,
    intent: &VoiceIntent,
    default_context: AudioContext,
    vt: &VoiceTarget,
    resolved_channels: &[ResolvedVoiceTargetChannel],
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    let channel_version = server.get_channels().current_version_in_server(server_id);
    let channel_acl_generation = server.get_channels().channel_acl_generation();
    let client_version = server.get_clients().current_version_in_server(server_id);
    let hide_users_without_traverse = server.get_hide_users_without_traverse();

    if let Some(recipients) = vt.cached_resolved_recipients(
        server_id,
        channel_version,
        channel_acl_generation,
        client_version,
        hide_users_without_traverse,
        source_channel,
    ) {
        return live_targets_from_cached_recipients(server, server_id, &recipients).await;
    }

    let targets = resolve_voice_intent_with_resolved_channels(
        server,
        Some(sender),
        server_id,
        sender_id,
        intent,
        default_context,
        Some(resolved_channels),
    )
    .await;
    vt.store_resolved_recipients(
        server_id,
        channel_version,
        channel_acl_generation,
        client_version,
        hide_users_without_traverse,
        source_channel,
        cacheable_recipients_from_targets(&targets),
    );
    targets
}

pub async fn route_voice(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, audio: &Audio) {
    let started_at = Instant::now();
    let sender_id = sender.get_session_id();
    let server_id = sender.server_id();
    let sender_channel = sender.get_current_channel_id();

    {
        let gs = sender.read_global_state();
        if gs.is_muted() || gs.is_suppressed() || gs.is_self_muted() {
            tracing::trace!(
                session = u32::from(sender_id),
                muted = gs.is_muted(),
                suppressed = gs.is_suppressed(),
                self_muted = gs.is_self_muted(),
                "not routing voice packet from muted/suppressed client"
            );
            return;
        }
    }

    tracing::trace!(
        session = u32::from(sender_id),
        channel = sender_channel,
        target = %audio.target,
        "routing voice packet"
    );

    let (
        intent,
        target_kind,
        send_s2s,
        route_kind,
        resolved_channels,
        voice_target,
        s2s_target_channels,
    ) = match audio.target {
        AudioTarget::Normal => (
            normal_intent(sender_channel),
            S2S_TARGET_NORMAL,
            true,
            VoiceRouteKind::Normal,
            None,
            None,
            None,
        ),
        AudioTarget::ServerLoopback => {
            let targets = [(sender.clone(), AudioContext::Normal)];
            flush_voice_batch(server, audio, &targets).await;
            super::metrics::record_route(
                VoiceRouteSource::Loopback,
                VoiceRouteKind::Loopback,
                targets.len(),
                started_at.elapsed(),
            );
            return;
        }
        AudioTarget::VoiceTarget(slot) => {
            let Some(vt) = sender.voice_target(slot) else {
                return;
            };
            if vt.is_empty() {
                return;
            }
            let resolved_channels =
                resolved_voice_target_channels(server, &server_id, sender_channel, &vt).await;
            let s2s_target_channels =
                if voice_target_is_current_channel_or_links(&vt, sender_channel) {
                    resolved_channels
                        .first()
                        .map(|channel| channel.channel_ids().to_vec())
                } else {
                    None
                };

            (
                target_intent(sender_channel, &vt),
                S2S_TARGET_SHOUT,
                true,
                VoiceRouteKind::Target,
                Some(resolved_channels),
                Some(vt),
                s2s_target_channels,
            )
        }
    };

    let default_context = audio_context_from_target_kind(target_kind);
    let targets = if let (Some(vt), Some(resolved_channels)) =
        (voice_target.as_ref(), resolved_channels.as_deref())
    {
        resolved_voice_target_recipients(
            server,
            sender,
            &server_id,
            sender_id,
            sender_channel,
            &intent,
            default_context,
            vt,
            resolved_channels,
        )
        .await
    } else {
        resolve_voice_intent_with_resolved_channels(
            server,
            Some(sender),
            &server_id,
            sender_id,
            &intent,
            default_context,
            resolved_channels.as_deref(),
        )
        .await
    };

    tracing::trace!(
        session = u32::from(sender_id),
        channel = sender_channel,
        count = targets.len(),
        "resolved local voice recipients"
    );
    let resolution_duration = started_at.elapsed();
    flush_voice_batch(server, audio, &targets).await;
    super::metrics::record_route_resolution(
        VoiceRouteSource::Local,
        route_kind,
        resolution_duration,
    );
    super::metrics::record_route(
        VoiceRouteSource::Local,
        route_kind,
        targets.len(),
        started_at.elapsed(),
    );

    if send_s2s {
        let encode_started_at = Instant::now();
        let payload = encode_s2s_voice_payload(audio);
        record_pipeline_stage(
            VoicePipelinePath::S2sForward,
            VoicePipelineStage::S2sPayloadEncode,
            encode_started_at,
        );
        let is_terminator = matches!(
            &audio.audio_payload,
            codec::AudioPayload::Opus(payload) if payload.is_terminator
        );
        let enqueue_started_at = Instant::now();
        let sent = if let Some(target_channels) = s2s_target_channels {
            server.s2s_manager().send_voice_for_target_channels(
                u32::from(sender_id),
                server_id.clone(),
                target_channels,
                target_kind,
                is_terminator,
                payload,
                intent,
            )
        } else {
            match intent.kind.as_ref() {
                Some(VoiceIntentKind::Normal(normal)) => {
                    server.s2s_manager().send_voice_for_channel(
                        u32::from(sender_id),
                        server_id.clone(),
                        normal.source_channel,
                        is_terminator,
                        payload,
                    )
                }
                _ => server.s2s_manager().send_voice_broadcast(
                    u32::from(sender_id),
                    server_id.clone(),
                    target_kind,
                    is_terminator,
                    payload,
                    intent,
                ),
            }
        };
        record_pipeline_stage(
            VoicePipelinePath::S2sForward,
            VoicePipelineStage::S2sGatewayEnqueue,
            enqueue_started_at,
        );
        super::metrics::record_s2s_forward(sent);
        if !sent {
            tracing::trace!("voice s2s send dropped: S2S gateway unavailable");
        }
    }
}

pub(crate) async fn route_s2s_voice_frame(
    server: &Arc<Box<Server>>,
    from_immediate: crate::types::NodeIdentifier,
    frame: VoiceFrame,
) {
    let started_at = Instant::now();
    let sender_id = crate::client::client_session_identifier::ClientSessionIdentifier::from(
        frame.sender_session,
    );
    let decoded = match Audio::decode(&frame.payload, Some(sender_id)) {
        Ok(audio) => audio,
        Err(e) => {
            tracing::trace!(
                from = from_immediate,
                sender = frame.sender_session,
                error = %e,
                "s2s voice frame decode failed"
            );
            return;
        }
    };

    let server_id = if frame.server_id.is_empty() {
        crate::types::default_server_id()
    } else {
        frame.server_id.clone()
    };
    let replicated_sender = server
        .get_clients()
        .get_client_in_server(&server_id, sender_id)
        .await;
    if server.get_hide_users_without_traverse() && replicated_sender.is_none() {
        tracing::trace!(
            from = from_immediate,
            sender = frame.sender_session,
            "dropping s2s voice frame from unknown sender under traverse visibility gate"
        );
        return;
    }
    let (intent, route_kind) = match frame.intent.clone() {
        Some(intent) => {
            let kind = match intent.kind.as_ref() {
                Some(VoiceIntentKind::Target(_)) => VoiceRouteKind::Target,
                Some(VoiceIntentKind::Normal(_)) | None => VoiceRouteKind::Normal,
            };
            (intent, kind)
        }
        None => {
            let source_channel = replicated_sender
                .as_ref()
                .map(|client| client.get_current_channel_id())
                .unwrap_or(0);
            (normal_intent(source_channel), VoiceRouteKind::Normal)
        }
    };

    let targets = resolve_s2s_voice_intent(
        server,
        replicated_sender.as_ref(),
        &server_id,
        sender_id,
        &intent,
        audio_context_from_target_kind(frame.target_kind),
    )
    .await;

    tracing::trace!(
        from = from_immediate,
        sender = frame.sender_session,
        target_kind = frame.target_kind,
        count = targets.len(),
        "routing s2s voice frame to local recipients"
    );
    let resolution_duration = started_at.elapsed();
    flush_voice_batch(server, &decoded, &targets).await;
    super::metrics::record_route_resolution(VoiceRouteSource::S2s, route_kind, resolution_duration);
    super::metrics::record_route(
        VoiceRouteSource::S2s,
        route_kind,
        targets.len(),
        started_at.elapsed(),
    );
}

#[derive(Default)]
struct VoiceTcpEgressTally {
    queued_packets: usize,
    queued_bytes: usize,
    dropped_packets: usize,
    dropped_bytes: usize,
}

impl VoiceTcpEgressTally {
    fn enqueue(&mut self, client: &Client, bytes: &Bytes) {
        if client.try_enqueue_voice_tcp(bytes.clone()) {
            self.queued_packets += 1;
            self.queued_bytes += bytes.len();
        } else {
            self.dropped_packets += 1;
            self.dropped_bytes += bytes.len();
        }
    }

    fn record(self) {
        if self.queued_packets > 0 {
            super::metrics::record_egress(
                VoiceEgressTransport::TcpTunnel,
                VoiceEgressResult::Queued,
                self.queued_packets,
                self.queued_bytes,
            );
        }
        if self.dropped_packets > 0 {
            super::metrics::record_egress(
                VoiceEgressTransport::TcpTunnel,
                VoiceEgressResult::Dropped,
                self.dropped_packets,
                self.dropped_bytes,
            );
        }
    }
}

fn record_udp_flush_stats(stats: udp_batch::FlushStats) {
    super::metrics::record_udp_send_result(
        VoiceUdpSendResult::WouldBlock,
        stats.would_block_count(),
    );
    super::metrics::record_udp_send_result(VoiceUdpSendResult::Partial, stats.partial_count());
}

fn record_pipeline_stage(path: VoicePipelinePath, stage: VoicePipelineStage, started_at: Instant) {
    super::metrics::record_pipeline_stage(path, stage, started_at.elapsed());
}

fn enqueue_voice_tcp_timed(
    path: VoicePipelinePath,
    tally: &mut VoiceTcpEgressTally,
    client: &Client,
    bytes: &Bytes,
) {
    let started_at = Instant::now();
    tally.enqueue(client, bytes);
    record_pipeline_stage(path, VoicePipelineStage::TcpEnqueue, started_at);
}

pub(crate) async fn flush_voice_batch(
    server: &Arc<Box<Server>>,
    audio: &Audio,
    targets: &[(Arc<Box<Client>>, AudioContext)],
) {
    if targets.is_empty() {
        return;
    }

    // Dispatch is per-recipient: UDP iff that recipient currently has a
    // bound UDP address and is not on the TCP-tunnel fallback. The
    // speaker's own ingest path is irrelevant — each recipient's
    // `prefers_tcp_tunnel` is already maintained based on whether *they*
    // can take UDP (see `set_prefer_tcp_tunnel` toggles).
    //
    // For small fan-outs (the common case), do everything on the routing
    // task: encode (cached), encrypt, queue. For large fan-outs, bucket
    // and dispatch the encrypt work to rayon inside spawn_blocking so
    // multiple cores share the load.
    let server_protocol_version = server.get_server_protocol_version();
    let udp_send_retry_budget = server.read_config().voice.udp_send_retry_budget();

    if targets.len() < RAYON_FANOUT_THRESHOLD {
        super::metrics::record_dispatch(VoiceDispatchMode::Sequential);
        let path = VoicePipelinePath::LocalSequential;
        let mut cache = EncodeCache::new();
        let mut udp_batches: HashMap<std::net::SocketAddr, DatagramBatch> = HashMap::new();
        let mut tcp_tally = VoiceTcpEgressTally::default();

        for (client, context) in targets {
            let format = client_packet_format(client, server_protocol_version);
            let encode_started_at = Instant::now();
            let entry = cache.get_or_encode(audio, *context, format);
            record_pipeline_stage(path, VoicePipelineStage::Encode, encode_started_at);

            let lookup_started_at = Instant::now();
            if client.prefers_tcp_tunnel() {
                record_pipeline_stage(path, VoicePipelineStage::RecipientLookup, lookup_started_at);
                enqueue_voice_tcp_timed(path, &mut tcp_tally, client, &entry.bytes);
                continue;
            }

            let Some(addr) = client.get_udp_address() else {
                record_pipeline_stage(path, VoicePipelineStage::RecipientLookup, lookup_started_at);
                enqueue_voice_tcp_timed(path, &mut tcp_tally, client, &entry.bytes);
                continue;
            };
            let Some(local_addr) = server
                .udp_socket_for_client(client)
                .and_then(|socket| socket.local_addr().ok())
            else {
                record_pipeline_stage(path, VoicePipelineStage::RecipientLookup, lookup_started_at);
                enqueue_voice_tcp_timed(path, &mut tcp_tally, client, &entry.bytes);
                continue;
            };
            record_pipeline_stage(path, VoicePipelineStage::RecipientLookup, lookup_started_at);

            let Some(mut crypt) = client.try_crypt_state() else {
                super::metrics::record_crypt_lock_contention_drop(1);
                super::metrics::record_egress(
                    VoiceEgressTransport::Udp,
                    VoiceEgressResult::Dropped,
                    1,
                    entry.bytes.len(),
                );
                continue;
            };
            let Some(state) = crypt.as_mut() else {
                continue;
            };
            let encrypted_len = entry.bytes.len() + state.overhead();
            let udp_batch = udp_batches
                .entry(local_addr)
                .or_insert_with(|| DatagramBatch::with_capacity(targets.len()));
            let encrypt_started_at = Instant::now();
            let encrypt_result = udp_batch.try_push_zeroed(addr, encrypted_len, |buf| {
                state.encrypt_with_precomputed_checksum(buf, &entry.bytes, &entry.checksum)
            });
            record_pipeline_stage(
                path,
                VoicePipelineStage::UdpEncryptQueue,
                encrypt_started_at,
            );
            if encrypt_result.is_err() {
                tracing::trace!(
                    session = u32::from(client.get_session_id()),
                    "encryption failed for client, falling back to TCP tunnel"
                );
                enqueue_voice_tcp_timed(path, &mut tcp_tally, client, &entry.bytes);
                continue;
            }
        }
        tcp_tally.record();

        for (local_addr, udp_batch) in udp_batches {
            if udp_batch.is_empty() {
                continue;
            }
            let packet_count = udp_batch.len();
            let byte_count = udp_batch.bytes_len();
            super::metrics::record_queue_status(
                super::metrics::VoiceQueueKind::UdpFanout,
                packet_count,
                targets.len(),
            );
            super::metrics::record_queue_enqueue(
                super::metrics::VoiceQueueKind::UdpFanout,
                super::metrics::VoiceQueueEnqueueResult::Accepted,
            );
            super::metrics::record_egress(
                VoiceEgressTransport::Udp,
                VoiceEgressResult::Queued,
                packet_count,
                byte_count,
            );
            let Some(socket) = server.udp_socket_for_client_addr(local_addr) else {
                tracing::warn!(%local_addr, "UDP batch has no matching local socket");
                super::metrics::record_egress(
                    VoiceEgressTransport::Udp,
                    VoiceEgressResult::Dropped,
                    packet_count,
                    byte_count,
                );
                continue;
            };
            let flush_started_at = Instant::now();
            match udp_batch::flush_batch_with_retry_budget(
                socket.as_ref(),
                &udp_batch,
                udp_send_retry_budget,
            )
            .await
            {
                Err(e) => {
                    let flush_duration = flush_started_at.elapsed();
                    super::metrics::record_udp_egress_batch(
                        packet_count,
                        byte_count,
                        flush_duration,
                    );
                    tracing::warn!("UDP batch send error: {e}");
                    super::metrics::record_egress(
                        VoiceEgressTransport::Udp,
                        VoiceEgressResult::Failed,
                        packet_count,
                        byte_count,
                    );
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        super::metrics::record_udp_send_result(
                            VoiceUdpSendResult::RetryBudgetExhausted,
                            1,
                        );
                    } else {
                        super::metrics::record_udp_send_result(VoiceUdpSendResult::Failed, 1);
                    }
                }
                Ok(stats) => {
                    let flush_duration = flush_started_at.elapsed();
                    super::metrics::record_udp_egress_batch(
                        packet_count,
                        byte_count,
                        flush_duration,
                    );
                    record_udp_flush_stats(stats);
                    super::metrics::record_egress(
                        VoiceEgressTransport::Udp,
                        VoiceEgressResult::Sent,
                        packet_count,
                        byte_count,
                    );
                }
            }
            record_pipeline_stage(path, VoicePipelineStage::UdpFlush, flush_started_at);
        }
        return;
    }

    super::metrics::record_dispatch(VoiceDispatchMode::Rayon);
    let path = VoicePipelinePath::LocalRayon;

    // Large-fanout path: bucket recipients while collecting unique
    // (format, context) keys, pre-encode each unique key once, then dispatch
    // the encrypt loop to rayon.
    let mut udp_items: Vec<(
        Arc<Box<Client>>,
        std::net::SocketAddr,
        std::net::SocketAddr,
        PacketFormat,
        AudioContext,
    )> = Vec::with_capacity(targets.len());
    let mut tcp_items: Vec<(Arc<Box<Client>>, PacketFormat, AudioContext)> = Vec::new();
    let mut cache = EncodeCache::new();

    for (client, context) in targets {
        let format = client_packet_format(client, server_protocol_version);
        // Touch the cache so every (format, context) seen is pre-encoded.
        let encode_started_at = Instant::now();
        let _ = cache.get_or_encode(audio, *context, format);
        record_pipeline_stage(path, VoicePipelineStage::Encode, encode_started_at);

        let lookup_started_at = Instant::now();
        if client.prefers_tcp_tunnel() {
            record_pipeline_stage(path, VoicePipelineStage::RecipientLookup, lookup_started_at);
            tcp_items.push((client.clone(), format, *context));
            continue;
        }
        match client.get_udp_address() {
            Some(addr) => {
                if let Some(local_addr) = server
                    .udp_socket_for_client(client)
                    .and_then(|socket| socket.local_addr().ok())
                {
                    record_pipeline_stage(
                        path,
                        VoicePipelineStage::RecipientLookup,
                        lookup_started_at,
                    );
                    udp_items.push((client.clone(), local_addr, addr, format, *context));
                } else {
                    record_pipeline_stage(
                        path,
                        VoicePipelineStage::RecipientLookup,
                        lookup_started_at,
                    );
                    tcp_items.push((client.clone(), format, *context));
                }
            }
            None => {
                record_pipeline_stage(path, VoicePipelineStage::RecipientLookup, lookup_started_at);
                tcp_items.push((client.clone(), format, *context));
            }
        }
    }

    // TCP fallback recipients — enqueue using the cached plaintext, do not await.
    let mut tcp_tally = VoiceTcpEgressTally::default();
    for (client, format, context) in &tcp_items {
        let encode_started_at = Instant::now();
        let entry = cache.get_or_encode(audio, *context, *format);
        record_pipeline_stage(path, VoicePipelineStage::Encode, encode_started_at);
        enqueue_voice_tcp_timed(path, &mut tcp_tally, client, &entry.bytes);
    }
    tcp_tally.record();

    if udp_items.is_empty() {
        return;
    }

    // Snapshot the cache as a plain Vec for the rayon closure. The Vec is
    // moved into `spawn_blocking`; rayon workers only borrow it during the
    // scoped parallel iteration, so no Arc wrapper is needed here.
    let plaintexts: Vec<((PacketFormat, AudioContext), Encoded)> = cache
        .slots
        .into_iter()
        .flatten()
        .chain(cache.overflow.into_iter())
        .collect();

    let rayon_started_at = Instant::now();
    let batches: HashMap<std::net::SocketAddr, DatagramBatch> =
        tokio::task::spawn_blocking(move || {
            use rayon::prelude::*;
            udp_items
                .into_par_iter()
                .with_min_len(RAYON_FANOUT_BATCH_MIN_LEN)
                .fold(
                    HashMap::<std::net::SocketAddr, DatagramBatch>::new,
                    |mut batches, (client, local_addr, addr, format, context)| {
                        let Some(entry) = plaintexts
                            .iter()
                            .find_map(|(k, e)| (*k == (format, context)).then_some(e))
                        else {
                            return batches;
                        };
                        let Some(mut crypt) = client.try_crypt_state() else {
                            super::metrics::record_crypt_lock_contention_drop(1);
                            super::metrics::record_egress(
                                VoiceEgressTransport::Udp,
                                VoiceEgressResult::Dropped,
                                1,
                                entry.bytes.len(),
                            );
                            return batches;
                        };
                        let Some(state) = crypt.as_mut() else {
                            return batches;
                        };
                        let encrypted_len = entry.bytes.len() + state.overhead();
                        let batch = batches.entry(local_addr).or_insert_with(DatagramBatch::new);
                        let encrypt_started_at = Instant::now();
                        let _ = batch.try_push_zeroed(addr, encrypted_len, |buf| {
                            state.encrypt_with_precomputed_checksum(
                                buf,
                                &entry.bytes,
                                &entry.checksum,
                            )
                        });
                        super::metrics::record_pipeline_stage(
                            path,
                            VoicePipelineStage::UdpEncryptQueue,
                            encrypt_started_at.elapsed(),
                        );
                        batches
                    },
                )
                .reduce(HashMap::new, |mut left, right| {
                    for (local_addr, batch) in right {
                        left.entry(local_addr)
                            .or_insert_with(DatagramBatch::new)
                            .append(batch);
                    }
                    left
                })
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("voice encrypt task join error: {e}");
            HashMap::new()
        });
    record_pipeline_stage(path, VoicePipelineStage::RayonEncryptJoin, rayon_started_at);

    for (local_addr, batch) in batches {
        if batch.is_empty() {
            continue;
        }
        let packet_count = batch.len();
        let byte_count = batch.bytes_len();
        super::metrics::record_queue_status(
            super::metrics::VoiceQueueKind::UdpFanout,
            packet_count,
            targets.len(),
        );
        super::metrics::record_queue_enqueue(
            super::metrics::VoiceQueueKind::UdpFanout,
            super::metrics::VoiceQueueEnqueueResult::Accepted,
        );
        super::metrics::record_egress(
            VoiceEgressTransport::Udp,
            VoiceEgressResult::Queued,
            packet_count,
            byte_count,
        );
        let Some(socket) = server.udp_socket_for_client_addr(local_addr) else {
            tracing::warn!(%local_addr, "UDP batch has no matching local socket");
            super::metrics::record_egress(
                VoiceEgressTransport::Udp,
                VoiceEgressResult::Dropped,
                packet_count,
                byte_count,
            );
            continue;
        };
        let flush_started_at = Instant::now();
        match udp_batch::flush_batch_with_retry_budget(
            socket.as_ref(),
            &batch,
            udp_send_retry_budget,
        )
        .await
        {
            Err(e) => {
                let flush_duration = flush_started_at.elapsed();
                super::metrics::record_udp_egress_batch(packet_count, byte_count, flush_duration);
                tracing::warn!("UDP batch send error: {e}");
                super::metrics::record_egress(
                    VoiceEgressTransport::Udp,
                    VoiceEgressResult::Failed,
                    packet_count,
                    byte_count,
                );
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    super::metrics::record_udp_send_result(
                        VoiceUdpSendResult::RetryBudgetExhausted,
                        1,
                    );
                } else {
                    super::metrics::record_udp_send_result(VoiceUdpSendResult::Failed, 1);
                }
            }
            Ok(stats) => {
                let flush_duration = flush_started_at.elapsed();
                super::metrics::record_udp_egress_batch(packet_count, byte_count, flush_duration);
                record_udp_flush_stats(stats);
                super::metrics::record_egress(
                    VoiceEgressTransport::Udp,
                    VoiceEgressResult::Sent,
                    packet_count,
                    byte_count,
                );
            }
        }
        record_pipeline_stage(path, VoicePipelineStage::UdpFlush, flush_started_at);
    }
}

/// Spawn a per-user voice routing task.
///
/// The receiver half of the queue is taken from `sender` (created in
/// `Client::new_local`).  The task holds a `Weak` reference to the client so
/// it does not prevent the client from being dropped — when all strong `Arc`s
/// are gone the weak upgrade fails, the loop exits, and the task cleans up.
pub fn spawn_voice_routing_task(server: Arc<Box<Server>>, sender: Arc<Box<Client>>) {
    let span = sender.tracing_span();
    let mut rx = match sender.take_voice_routing_rx() {
        Some(rx) => rx,
        None => {
            span.in_scope(|| {
                tracing::error!(
                    session = u32::from(sender.get_session_id()),
                    "voice routing task already spawned"
                );
            });
            return;
        }
    };
    let weak_sender = Arc::downgrade(&sender);
    tokio::spawn(
        async move {
            while let Some(payload) = rx.recv().await {
                let Some(sender) = weak_sender.upgrade() else {
                    break;
                };
                let queue_age = payload.enqueue_age();
                super::metrics::record_packet_age(VoiceAgeStage::RoutingQueue, queue_age);
                super::metrics::record_scheduler_delay(VoiceSchedulerStage::RoutingTask, queue_age);
                if queue_age > server.read_config().voice.max_routing_queue_age() {
                    super::metrics::record_stale_drop(VoiceAgeStage::RoutingQueue);
                    continue;
                }
                route_voice(&server, &sender, payload.decoded_audio()).await;
            }
        }
        .instrument(span),
    );
}

/// Spawn a fallback per-user voice TCP send task.
///
/// Native TLS clients drain the separate `voice_tcp` queue in their connection
/// writer task. Gateway transports do not have that writer, so this bridge
/// forwards queued `UDPTunnel` payloads through the transport's queued send
/// API.
///
/// Holds a `Weak` reference to the client so the task does not prevent
/// client drop; on a failed upgrade or a write error, the task exits.
pub fn spawn_voice_tcp_task(client: Arc<Box<Client>>) {
    let span = client.tracing_span();
    let mut rx = match client.take_voice_tcp_rx() {
        Some(rx) => rx,
        None => {
            span.in_scope(|| {
                tracing::warn!(
                    session = u32::from(client.get_session_id()),
                    "voice TCP send task already spawned"
                );
            });
            return;
        }
    };
    let weak_client = Arc::downgrade(&client);
    tokio::spawn(
        async move {
            while let Some(raw) = rx.recv().await {
                let Some(client) = weak_client.upgrade() else {
                    break;
                };
                let message = crate::messages::Message::UDPTunnel(raw);
                if let Err(e) = client.write_proto_message(&message).await {
                    tracing::trace!(
                        session = u32::from(client.get_session_id()),
                        error = %e,
                        "voice TCP send failed, terminating send task"
                    );
                    break;
                }
            }
        }
        .instrument(span),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_s2s_normal_cache_key() -> S2SVoiceNormalResolutionCacheKey {
        S2SVoiceNormalResolutionCacheKey {
            server_identity: 1,
            local_node_id: 2,
            server_id: "default".to_owned(),
            sender_session: ClientSessionIdentifier::from(0x0002_0001),
            sender_instance_id: Some(7),
            channel_version: 11,
            channel_acl_generation: 13,
            client_version: 17,
            hide_users_without_traverse: false,
            source_channel: 19,
        }
    }

    #[test]
    fn s2s_normal_cache_key_scopes_routing_versions_and_sender() {
        let base = base_s2s_normal_cache_key();

        let mut changed = base.clone();
        changed.sender_instance_id = Some(8);
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.channel_version += 1;
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.channel_acl_generation += 1;
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.client_version += 1;
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.hide_users_without_traverse = true;
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.source_channel += 1;
        assert_ne!(base, changed);
    }

    #[test]
    fn adaptive_hash_cache_grows_under_insert_pressure() {
        let cache = AdaptiveHashCache::new(64, 256);
        let initial_capacity = cache.current_max_capacity();

        for key in 0..=(initial_capacity * 3 / 4) {
            cache.put(key as u32, key as u32);
        }

        assert!(cache.current_max_capacity() > initial_capacity);
        assert_eq!(cache.read(&0, |_, value| *value), Some(0));
        assert_eq!(
            cache.read(&((initial_capacity * 3 / 4) as u32), |_, value| *value),
            Some((initial_capacity * 3 / 4) as u32)
        );
    }
}
