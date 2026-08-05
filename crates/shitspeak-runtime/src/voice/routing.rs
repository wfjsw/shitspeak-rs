//! Voice routing logic — determines recipients and dispatches audio packets.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use parking_lot::{Mutex, RwLock};
use scc::HashCache;
use shitspeak_client_crypto::CryptState;
use tokio::sync::Notify;
use tracing::Instrument;

use super::codec::{self, Audio, PacketFormat};
use super::dispatch_tuning::{RayonChunkPlan, VoiceDispatchProfile};
use super::metrics::{
    VoiceAgeStage, VoiceDispatchMode, VoiceEgressResult, VoiceEgressTransport, VoicePipelinePath,
    VoicePipelineStage, VoiceRouteCacheLayer, VoiceRouteKind, VoiceRouteScope, VoiceRouteSource,
    VoiceSchedulerStage, VoiceUdpSendResult,
};
use super::udp_batch::{self, DatagramBatch};
use crate::{
    client::{
        Client, ClientInstanceId, VoiceTcpEnqueueResult,
        client_session_identifier::ClientSessionIdentifier,
        voice_target::{
            AuthorizedVoiceTarget, CachedVoiceTargetRecipient, ResolvedVoiceTargetChannel,
            VoiceTarget,
        },
    },
    constants::PROTOBUF_INTRODUCED_VERSION,
    messages::encoder::{Audio as AudioWire, AudioContext, AudioHeader, AudioTarget},
    server::Server,
};
use shitspeak_s2s::application::proto::{
    VoiceFrame, VoiceIntent, VoiceIntentKind, VoiceIntentNormal, VoiceIntentTarget,
    VoiceTargetChannel as S2SVoiceTargetChannel,
};

const S2S_RECIPIENT_CACHE_INITIAL_CAPACITY: usize = 256;
const S2S_RECIPIENT_CACHE_MAX_CAPACITY: usize = 65536;

static S2S_TARGET_RECIPIENT_CACHE: LazyLock<
    AdaptiveHashCache<S2SVoiceTargetResolutionCacheKey, Arc<[CachedVoiceTargetRecipient]>>,
> = LazyLock::new(|| {
    AdaptiveHashCache::new(
        S2S_RECIPIENT_CACHE_INITIAL_CAPACITY,
        S2S_RECIPIENT_CACHE_MAX_CAPACITY,
    )
});

static S2S_NORMAL_RECIPIENT_CACHE: LazyLock<
    AdaptiveHashCache<S2SVoiceNormalResolutionCacheKey, Arc<[CachedVoiceTargetRecipient]>>,
> = LazyLock::new(|| {
    AdaptiveHashCache::new(
        S2S_RECIPIENT_CACHE_INITIAL_CAPACITY,
        S2S_RECIPIENT_CACHE_MAX_CAPACITY,
    )
});

// The routing-age policy remains the realtime bound. Sixteen entries let a
// 20 ms talkspurt absorb a scheduler stall up to that policy limit instead of
// evicting frames after only 160 ms.
const LOCAL_FANOUT_QUEUE_CAPACITY: usize = 16;
enum BoundedPushResult<T> {
    Accepted,
    EvictedNonTerminator,
    NeedsSpace(T),
}

fn push_bounded<T>(
    entries: &mut VecDeque<T>,
    capacity: usize,
    item: T,
    is_terminator: impl Fn(&T) -> bool,
) -> BoundedPushResult<T> {
    debug_assert!(capacity > 0);
    if entries.len() == capacity {
        let Some(index) = entries.iter().position(|entry| !is_terminator(entry)) else {
            return BoundedPushResult::NeedsSpace(item);
        };
        entries.remove(index);
        entries.push_back(item);
        return BoundedPushResult::EvictedNonTerminator;
    }
    entries.push_back(item);
    BoundedPushResult::Accepted
}

fn audio_is_terminator(audio: &Audio) -> bool {
    matches!(
        &audio.audio_payload,
        codec::AudioPayload::Opus(payload) if payload.is_terminator
    )
}

struct LocalFanoutWork {
    audio: Audio,
    targets: Arc<[(Arc<Box<Client>>, AudioContext)]>,
    server_id: String,
    sender_id: ClientSessionIdentifier,
    sender_instance_id: ClientInstanceId,
    voice_target_definition_id: Option<u64>,
    generation: LocalFanoutGeneration,
    route_kind: VoiceRouteKind,
    route_started_at: Instant,
    age_at_enqueue: Duration,
    enqueued_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
struct LocalFanoutGeneration {
    channel_version: u64,
    channel_acl_generation: u64,
    voice_routing_generation: u64,
    sender_acl_generation: u64,
    sender_channel: u32,
}

impl LocalFanoutGeneration {
    fn capture(
        server: &Arc<Box<Server>>,
        sender: &Client,
        server_id: &str,
        sender_channel: u32,
    ) -> Self {
        Self {
            channel_version: server.get_channels().current_version_in_server(server_id),
            channel_acl_generation: server.get_channels().channel_acl_generation(),
            voice_routing_generation: server
                .get_clients()
                .voice_routing_generation_in_server(server_id),
            sender_acl_generation: sender.get_acl_generation(),
            sender_channel,
        }
    }
}

fn local_fanout_snapshot_is_current(
    expected_instance_id: ClientInstanceId,
    expected_generation: &LocalFanoutGeneration,
    route_kind: VoiceRouteKind,
    current: Option<(ClientInstanceId, &LocalFanoutGeneration)>,
) -> bool {
    current.is_some_and(|(instance_id, generation)| {
        instance_id == expected_instance_id
            && (!matches!(route_kind, VoiceRouteKind::Target)
                || (generation.channel_version == expected_generation.channel_version
                    && generation.voice_routing_generation
                        == expected_generation.voice_routing_generation))
            && generation.channel_acl_generation == expected_generation.channel_acl_generation
            && generation.sender_acl_generation == expected_generation.sender_acl_generation
            && generation.sender_channel == expected_generation.sender_channel
    })
}

fn voice_target_definition_is_current(
    route_kind: VoiceRouteKind,
    expected_definition_id: Option<u64>,
    current_definition_id: Option<u64>,
) -> bool {
    !matches!(route_kind, VoiceRouteKind::Target)
        || expected_definition_id
            .zip(current_definition_id)
            .is_some_and(|(expected, current)| expected == current)
}

fn voice_target_definition_id(sender: &Client, target: &AudioTarget) -> Option<u64> {
    match target {
        AudioTarget::VoiceTarget(slot) => sender
            .voice_target(*slot)
            .map(|target| target.definition_id()),
        _ => None,
    }
}

struct LocalFanoutQueue {
    state: Mutex<LocalFanoutQueueState>,
    changed: Notify,
    space_available: Notify,
}

struct LocalFanoutQueueState {
    entries: VecDeque<LocalFanoutWork>,
    closed: bool,
}

impl LocalFanoutQueue {
    fn new() -> Self {
        super::metrics::record_queue_instance_created(
            super::metrics::VoiceQueueKind::LocalFanout,
            LOCAL_FANOUT_QUEUE_CAPACITY,
        );
        Self {
            state: Mutex::new(LocalFanoutQueueState {
                entries: VecDeque::with_capacity(LOCAL_FANOUT_QUEUE_CAPACITY),
                closed: false,
            }),
            changed: Notify::new(),
            space_available: Notify::new(),
        }
    }

    async fn push(&self, mut work: LocalFanoutWork) {
        loop {
            let space_available = self.space_available.notified();
            let incoming_is_terminator = audio_is_terminator(&work.audio);
            let result = {
                let mut state = self.state.lock();
                if state.closed {
                    super::metrics::record_queue_enqueue(
                        super::metrics::VoiceQueueKind::LocalFanout,
                        super::metrics::VoiceQueueEnqueueResult::Closed,
                    );
                    return;
                }
                push_bounded(
                    &mut state.entries,
                    LOCAL_FANOUT_QUEUE_CAPACITY,
                    work,
                    |entry| audio_is_terminator(&entry.audio),
                )
            };
            match result {
                BoundedPushResult::Accepted => {
                    super::metrics::record_queue_depth_change(
                        super::metrics::VoiceQueueKind::LocalFanout,
                        1,
                    );
                }
                BoundedPushResult::EvictedNonTerminator => {
                    super::metrics::record_queue_full_sample(
                        super::metrics::VoiceQueueKind::LocalFanout,
                    );
                    super::metrics::record_queue_enqueue(
                        super::metrics::VoiceQueueKind::LocalFanout,
                        super::metrics::VoiceQueueEnqueueResult::Dropped,
                    );
                }
                BoundedPushResult::NeedsSpace(returned) if incoming_is_terminator => {
                    super::metrics::record_queue_full_sample(
                        super::metrics::VoiceQueueKind::LocalFanout,
                    );
                    work = returned;
                    space_available.await;
                    continue;
                }
                BoundedPushResult::NeedsSpace(_) => {
                    super::metrics::record_queue_full_sample(
                        super::metrics::VoiceQueueKind::LocalFanout,
                    );
                    super::metrics::record_queue_enqueue(
                        super::metrics::VoiceQueueKind::LocalFanout,
                        super::metrics::VoiceQueueEnqueueResult::Dropped,
                    );
                    return;
                }
            }
            super::metrics::record_queue_enqueue(
                super::metrics::VoiceQueueKind::LocalFanout,
                super::metrics::VoiceQueueEnqueueResult::Accepted,
            );
            self.changed.notify_one();
            return;
        }
    }

    async fn pop(&self) -> Option<LocalFanoutWork> {
        loop {
            let notified = self.changed.notified();
            {
                let mut state = self.state.lock();
                if let Some(work) = state.entries.pop_front() {
                    super::metrics::record_queue_depth_change(
                        super::metrics::VoiceQueueKind::LocalFanout,
                        -1,
                    );
                    self.space_available.notify_one();
                    return Some(work);
                }
                if state.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    fn close(&self) {
        self.state.lock().closed = true;
        self.changed.notify_waiters();
        self.space_available.notify_waiters();
    }
}

impl Drop for LocalFanoutQueue {
    fn drop(&mut self) {
        super::metrics::record_queue_instance_closed(
            super::metrics::VoiceQueueKind::LocalFanout,
            LOCAL_FANOUT_QUEUE_CAPACITY,
            self.state.get_mut().entries.len(),
        );
    }
}

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

    #[cfg(test)]
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
    voice_routing_generation: u64,
    sender_acl_generation: Option<u64>,
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
    voice_routing_generation: u64,
    sender_acl_generation: u64,
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

type UdpVoiceRecipient = (
    Arc<Box<Client>>,
    std::net::SocketAddr,
    std::net::SocketAddr,
    PacketFormat,
    AudioContext,
);
type VoicePlaintext = ((PacketFormat, AudioContext), Encoded);

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

fn authorized_target_intent(
    source_channel: u32,
    vt: &VoiceTarget,
    authorized_channels: &[ResolvedVoiceTargetChannel],
) -> VoiceIntent {
    VoiceIntent {
        kind: Some(VoiceIntentKind::Target(VoiceIntentTarget {
            source_channel,
            sessions: vt.sessions().to_vec(),
            channels: vt
                .channels()
                .iter()
                .zip(authorized_channels)
                .filter(|(_, resolved)| resolved.is_authorized())
                .map(|(channel, _)| S2SVoiceTargetChannel {
                    id: channel.id(),
                    children: channel.sub_channels(),
                    links: channel.links(),
                    group: channel.only_group().to_owned(),
                })
                .collect(),
        })),
    }
}

fn s2s_target_channels(
    vt: &VoiceTarget,
    authorized_channels: &[ResolvedVoiceTargetChannel],
) -> Option<Arc<[u32]>> {
    if authorized_channels
        .iter()
        .any(|channel| channel.is_authorized() && channel.is_whole_server())
    {
        return Some(Arc::from([]));
    }
    if !vt.sessions().is_empty() {
        return None;
    }
    let mut channel_ids = authorized_channels
        .iter()
        .filter(|channel| channel.is_authorized())
        .flat_map(|channel| channel.channel_ids().iter().copied())
        .collect::<Vec<_>>();
    channel_ids.sort_unstable();
    channel_ids.dedup();
    (!channel_ids.is_empty()).then(|| Arc::from(channel_ids))
}

fn voice_intent_scope(intent: &VoiceIntent) -> VoiceRouteScope {
    match intent.kind.as_ref() {
        Some(VoiceIntentKind::Target(target))
            if target
                .channels
                .iter()
                .any(|channel| channel.id == 0 && channel.children) =>
        {
            VoiceRouteScope::WholeServer
        }
        Some(VoiceIntentKind::Target(_)) => VoiceRouteScope::TargetChannel,
        Some(VoiceIntentKind::Normal(_)) | None => VoiceRouteScope::Normal,
    }
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
    let evaluation = shitspeak_state::ChannelHierarchy::new(evaluation_channel, &eval_ancestors);
    let home = shitspeak_state::ChannelHierarchy::new(home_channel_id, &home_ancestors);
    let membership = shitspeak_state::ClientMembershipQuery::new(
        &group_refs,
        client.get_user_id().is_some(),
        &token_refs,
        client.get_certificate_hash(),
        client.is_verified(),
        Some(client.get_real_ip_address()),
    )
    .with_home_channel(home);
    shitspeak_state::is_member_in_group(group, evaluation, Some(evaluation), &[], &membership)
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
    if !client.is_authenticated() || !client.is_published() {
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

fn live_targets_from_local_fanout_snapshot(
    targets: &[(Arc<Box<Client>>, AudioContext)],
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    targets
        .iter()
        .filter(|(client, _)| {
            !client.is_removed()
                && client.is_authenticated()
                && client.is_published()
                && client.read_local_state().is_some()
                && client.can_receive_voice()
        })
        .cloned()
        .collect()
}

fn live_targets_from_cached_local_recipients(
    recipients: &[CachedVoiceTargetRecipient],
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    let mut targets = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let Some(client) = recipient.upgrade() else {
            continue;
        };
        if client.get_session_id() != recipient.session_id()
            || client.client_instance_id() != recipient.client_instance_id()
            || client.is_removed()
            || !client.is_authenticated()
            || !client.is_published()
            || !client.read_local_state().is_some()
            || !client.can_receive_voice()
        {
            continue;
        }
        targets.push((client, recipient.context()));
    }
    targets
}

fn cacheable_local_recipients_from_targets(
    targets: &[(Arc<Box<Client>>, AudioContext)],
) -> Arc<[CachedVoiceTargetRecipient]> {
    targets
        .iter()
        .map(|(client, context)| CachedVoiceTargetRecipient::new(client, *context))
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
        None,
        false,
        true,
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
        voice_routing_generation: server
            .get_clients()
            .voice_routing_generation_in_server(server_id),
        sender_acl_generation: sender.map(|sender| sender.get_acl_generation()),
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
        voice_routing_generation: server
            .get_clients()
            .voice_routing_generation_in_server(server_id),
        sender_acl_generation: sender.get_acl_generation(),
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
            super::metrics::record_route_cache(
                VoiceRouteSource::S2s,
                VoiceRouteCacheLayer::Recipients,
                true,
            );
            return live_targets_from_cached_local_recipients(&recipients);
        }
        super::metrics::record_route_cache(
            VoiceRouteSource::S2s,
            VoiceRouteCacheLayer::Recipients,
            false,
        );

        let targets = resolve_voice_intent(
            server,
            sender,
            server_id,
            sender_id,
            intent,
            default_context,
        )
        .await;
        S2S_TARGET_RECIPIENT_CACHE
            .put(cache_key, cacheable_local_recipients_from_targets(&targets));
        return targets;
    }

    if let Some(cache_key) =
        s2s_normal_resolution_cache_key(server, sender, server_id, sender_id, intent)
    {
        if let Some(recipients) =
            S2S_NORMAL_RECIPIENT_CACHE.read(&cache_key, |_, recipients| recipients.clone())
        {
            super::metrics::record_route_cache(
                VoiceRouteSource::S2s,
                VoiceRouteCacheLayer::Recipients,
                true,
            );
            return live_targets_from_cached_local_recipients(&recipients);
        }
        super::metrics::record_route_cache(
            VoiceRouteSource::S2s,
            VoiceRouteCacheLayer::Recipients,
            false,
        );

        let targets = resolve_voice_intent(
            server,
            sender,
            server_id,
            sender_id,
            intent,
            default_context,
        )
        .await;
        S2S_NORMAL_RECIPIENT_CACHE
            .put(cache_key, cacheable_local_recipients_from_targets(&targets));
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
    normal_channel_ids: Option<&[u32]>,
    resolved_channels: Option<&[ResolvedVoiceTargetChannel]>,
    preauthorized_channels: bool,
    preauthorized_whole_server: bool,
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let local_node_id = server.get_clients().local_node_id();
    let sender_instance_id = sender.map(|sender| sender.client_instance_id());

    match intent.kind.as_ref() {
        Some(VoiceIntentKind::Normal(normal)) => {
            let source_channel = normal.source_channel;
            let owned_normal_channel_ids;
            let normal_channel_ids = if let Some(channel_ids) = normal_channel_ids {
                channel_ids
            } else {
                owned_normal_channel_ids =
                    resolve_normal_voice_channels(server, sender, server_id, source_channel).await;
                &owned_normal_channel_ids
            };
            let channel_clients = server
                .get_clients()
                .get_local_clients_in_channels_in_server(server_id, normal_channel_ids)
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
                        if !perms.contains(shitspeak_state::ACLPermissions::Whisper) {
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
                if !resolved_channel.is_authorized() {
                    continue;
                }
                if resolved_channel.is_whole_server() {
                    let allowed = if preauthorized_channels || preauthorized_whole_server {
                        true
                    } else if let Some(sender) = sender {
                        let permissions =
                            crate::client::acl::compute_permissions_for_client(server, sender, 0)
                                .await;
                        if target.source_channel == 0 {
                            permissions.contains(shitspeak_state::ACLPermissions::Speak)
                        } else {
                            permissions.contains(shitspeak_state::ACLPermissions::Whisper)
                        }
                    } else {
                        true
                    };
                    if !allowed {
                        continue;
                    }

                    let clients = server
                        .get_clients()
                        .get_local_clients_in_server(server_id)
                        .await;
                    for client in clients {
                        let evaluation_channel = client.get_current_channel_id();
                        if !client_matches_voice_target_group(
                            server,
                            &client,
                            server_id,
                            evaluation_channel,
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
                            AudioContext::Shout,
                        );
                    }
                    continue;
                }

                let mut channel_ids = resolved_channel.channel_ids().to_vec();

                if let Some(sender) = sender {
                    let (allowed_channels, allowed_channel_set) = if preauthorized_channels {
                        (
                            channel_ids,
                            resolved_channel.channel_ids().iter().copied().collect(),
                        )
                    } else {
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
                                perms.contains(shitspeak_state::ACLPermissions::Speak)
                            } else {
                                perms.contains(shitspeak_state::ACLPermissions::Whisper)
                            };
                            if allowed && allowed_channel_set.insert(channel_id) {
                                allowed_channels.push(channel_id);
                            }
                        }
                        (allowed_channels, allowed_channel_set)
                    };
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

                    let listener_entries = server
                        .get_clients()
                        .get_local_listener_entries_for_channels_in_server(server_id, &channel_ids)
                        .await;
                    for (channel_id, client) in listener_entries {
                        if !client_matches_voice_target_group(
                            server,
                            &client,
                            server_id,
                            channel_id,
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
                            AudioContext::Listen,
                        );
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

                let listener_entries = server
                    .get_clients()
                    .get_local_listener_entries_for_channels_in_server(server_id, &channel_ids)
                    .await;
                for (channel_id, client) in listener_entries {
                    if !client_matches_voice_target_group(
                        server,
                        &client,
                        server_id,
                        channel_id,
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
                        AudioContext::Listen,
                    );
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

/// Resolve the channel set for ordinary speech. The source channel is always
/// included; linked channels require the speaker to hold Speak there.
async fn resolve_normal_voice_channels(
    server: &Arc<Box<Server>>,
    sender: Option<&Arc<Box<Client>>>,
    server_id: &str,
    source_channel: u32,
) -> Arc<[u32]> {
    let mut channel_ids = vec![source_channel];
    let Some(sender) = sender else {
        return channel_ids.into();
    };

    let linked_ids = server
        .get_channels()
        .effective_link_group_in_server(server_id, source_channel);
    for linked_id in linked_ids.iter().flat_map(|group| group.iter()).copied() {
        if linked_id == source_channel {
            continue;
        }
        let permissions =
            crate::client::acl::compute_permissions_for_client(server, sender, linked_id).await;
        if permissions.contains(shitspeak_state::ACLPermissions::Speak) {
            channel_ids.push(linked_id);
        }
    }

    channel_ids.into()
}

async fn resolve_voice_target_channel(
    server: &Arc<Box<Server>>,
    server_id: &str,
    source_channel: u32,
    ch_target: &S2SVoiceTargetChannel,
) -> ResolvedVoiceTargetChannel {
    if ch_target.id == 0 && ch_target.children {
        return ResolvedVoiceTargetChannel::whole_server(ch_target.group.clone());
    }

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
        super::metrics::record_route_cache(
            VoiceRouteSource::Local,
            VoiceRouteCacheLayer::Topology,
            true,
        );
        return channels;
    }
    super::metrics::record_route_cache(
        VoiceRouteSource::Local,
        VoiceRouteCacheLayer::Topology,
        false,
    );

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

async fn authorized_voice_target_channels(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    server_id: &str,
    source_channel: u32,
    vt: &VoiceTarget,
    resolved_channels: &[ResolvedVoiceTargetChannel],
) -> AuthorizedVoiceTarget {
    let channel_version = server.get_channels().current_version_in_server(server_id);
    let channel_acl_generation = server.get_channels().channel_acl_generation();
    let sender_acl_generation = sender.get_acl_generation();
    if let Some(target) = vt.cached_authorized_target(
        server_id,
        channel_version,
        channel_acl_generation,
        sender_acl_generation,
        source_channel,
    ) {
        super::metrics::record_route_cache(
            VoiceRouteSource::Local,
            VoiceRouteCacheLayer::Authorization,
            true,
        );
        return target;
    }
    super::metrics::record_route_cache(
        VoiceRouteSource::Local,
        VoiceRouteCacheLayer::Authorization,
        false,
    );

    let mut authorized = Vec::with_capacity(resolved_channels.len());
    for channel in resolved_channels {
        if channel.is_whole_server() {
            let permissions =
                crate::client::acl::compute_permissions_for_client(server, sender, 0).await;
            let allowed = if source_channel == 0 {
                permissions.contains(shitspeak_state::ACLPermissions::Speak)
            } else {
                permissions.contains(shitspeak_state::ACLPermissions::Whisper)
            };
            authorized.push(if allowed {
                channel.clone()
            } else {
                ResolvedVoiceTargetChannel::denied_like(channel)
            });
            continue;
        }

        let mut allowed_ids = Vec::new();
        for &channel_id in channel.channel_ids() {
            let permissions =
                crate::client::acl::compute_permissions_for_client(server, sender, channel_id)
                    .await;
            let allowed = if channel.current_channel_talk() && channel_id == source_channel {
                permissions.contains(shitspeak_state::ACLPermissions::Speak)
            } else {
                permissions.contains(shitspeak_state::ACLPermissions::Whisper)
            };
            if allowed {
                allowed_ids.push(channel_id);
            }
        }
        authorized.push(if allowed_ids.is_empty() {
            ResolvedVoiceTargetChannel::denied_like(channel)
        } else {
            ResolvedVoiceTargetChannel::new(
                channel.id(),
                channel.group().to_owned(),
                channel.current_channel_talk(),
                allowed_ids,
            )
        });
    }

    let authorized: Arc<[ResolvedVoiceTargetChannel]> = Arc::from(authorized);
    let target = AuthorizedVoiceTarget::new(
        authorized.clone(),
        s2s_target_channels(vt, &authorized),
        !vt.sessions().is_empty() || authorized.iter().any(|channel| channel.is_authorized()),
    );
    vt.store_authorized_target(
        server_id,
        channel_version,
        channel_acl_generation,
        sender_acl_generation,
        source_channel,
        target.clone(),
    );
    target
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
    let client_version = server
        .get_clients()
        .voice_routing_generation_in_server(server_id);
    let sender_acl_generation = sender.get_acl_generation();
    let hide_users_without_traverse = server.get_hide_users_without_traverse();

    if let Some(recipients) = vt.cached_resolved_recipients(
        server_id,
        channel_version,
        channel_acl_generation,
        client_version,
        sender_acl_generation,
        hide_users_without_traverse,
        source_channel,
    ) {
        super::metrics::record_route_cache(
            VoiceRouteSource::Local,
            VoiceRouteCacheLayer::Recipients,
            true,
        );
        return live_targets_from_cached_local_recipients(&recipients);
    }
    super::metrics::record_route_cache(
        VoiceRouteSource::Local,
        VoiceRouteCacheLayer::Recipients,
        false,
    );

    let targets = resolve_voice_intent_with_resolved_channels(
        server,
        Some(sender),
        server_id,
        sender_id,
        intent,
        default_context,
        None,
        Some(resolved_channels),
        true,
        true,
    )
    .await;
    vt.store_resolved_recipients(
        server_id,
        channel_version,
        channel_acl_generation,
        client_version,
        sender_acl_generation,
        hide_users_without_traverse,
        source_channel,
        cacheable_local_recipients_from_targets(&targets),
    );
    targets
}

pub async fn route_voice(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, audio: &Audio) {
    route_voice_inner(server, sender, audio, Duration::ZERO, None).await;
}

fn client_voice_blocked(client: &Arc<Box<Client>>) -> bool {
    let state = client.read_global_state();
    state.is_muted() || state.is_suppressed() || state.is_self_muted()
}

async fn route_voice_inner(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    audio: &Audio,
    ingress_age: Duration,
    local_fanout_queue: Option<&LocalFanoutQueue>,
) {
    let started_at = Instant::now();
    let sender_id = sender.get_session_id();
    if !sender.is_authenticated() || !sender.is_published() || sender.is_removed() {
        tracing::trace!(
            session = u32::from(sender_id),
            "not routing voice packet from inactive client"
        );
        return;
    }
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
    let local_fanout_generation =
        LocalFanoutGeneration::capture(server, sender, &server_id, sender_channel);

    let (
        intent,
        target_kind,
        send_s2s,
        route_kind,
        normal_channel_ids,
        resolved_channels,
        voice_target,
    ) = match audio.target {
        AudioTarget::Normal => {
            let normal_channel_ids =
                resolve_normal_voice_channels(server, Some(sender), &server_id, sender_channel)
                    .await;
            (
                normal_intent(sender_channel),
                S2S_TARGET_NORMAL,
                true,
                VoiceRouteKind::Normal,
                Some(normal_channel_ids),
                None,
                None,
            )
        }
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

            (
                target_intent(sender_channel, &vt),
                S2S_TARGET_SHOUT,
                true,
                VoiceRouteKind::Target,
                None,
                Some(resolved_channels),
                Some(vt),
            )
        }
    };

    let default_context = audio_context_from_target_kind(target_kind);
    let authorized_channels = if let (Some(vt), Some(resolved_channels)) =
        (voice_target.as_ref(), resolved_channels.as_deref())
    {
        Some(
            authorized_voice_target_channels(
                server,
                sender,
                &server_id,
                sender_channel,
                vt,
                resolved_channels,
            )
            .await,
        )
    } else {
        None
    };
    let targets = if let (Some(vt), Some(authorized_target)) =
        (voice_target.as_ref(), authorized_channels.as_ref())
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
            authorized_target.channels(),
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
            normal_channel_ids.as_deref(),
            resolved_channels.as_deref(),
            false,
            false,
        )
        .await
    };
    let has_authorized_s2s_target = authorized_channels
        .as_ref()
        .map(AuthorizedVoiceTarget::has_authorized_target)
        .unwrap_or(true);
    let s2s_target_channels = authorized_channels
        .as_ref()
        .and_then(AuthorizedVoiceTarget::s2s_channel_ids)
        .or(normal_channel_ids);
    let s2s_intent = match (voice_target.as_ref(), authorized_channels.as_ref()) {
        (Some(vt), Some(target)) => authorized_target_intent(sender_channel, vt, target.channels()),
        _ => intent.clone(),
    };
    let queued_voice_target_definition_id = voice_target.as_ref().map(VoiceTarget::definition_id);

    tracing::trace!(
        session = u32::from(sender_id),
        channel = sender_channel,
        count = targets.len(),
        "resolved local voice recipients"
    );
    let resolution_duration = started_at.elapsed();
    super::metrics::record_route_resolution(
        VoiceRouteSource::Local,
        route_kind,
        resolution_duration,
    );
    super::metrics::record_route_scope(VoiceRouteSource::Local, voice_intent_scope(&intent));

    // Resolution can await repository and ACL work. Recheck immediately
    // before either delivery path so a newly applied suppression wins.
    if client_voice_blocked(sender)
        || !voice_target_definition_is_current(
            route_kind,
            queued_voice_target_definition_id,
            voice_target_definition_id(sender, &audio.target),
        )
    {
        return;
    }

    if send_s2s && has_authorized_s2s_target {
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
        super::metrics::record_packet_age(
            VoiceAgeStage::S2sEnqueue,
            ingress_age.saturating_add(started_at.elapsed()),
        );
        let sent = if let Some(target_channels) = s2s_target_channels {
            server.s2s_manager().send_voice_for_target_channels(
                u32::from(sender_id),
                server_id.clone(),
                target_channels,
                target_kind,
                is_terminator,
                payload,
                s2s_intent,
            )
        } else {
            match s2s_intent.kind.as_ref() {
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
                    s2s_intent,
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

    if let Some(queue) = local_fanout_queue {
        let targets = Arc::from(targets);
        queue
            .push(LocalFanoutWork {
                audio: audio.clone(),
                targets,
                server_id: server_id.clone(),
                sender_id,
                sender_instance_id: sender.client_instance_id(),
                voice_target_definition_id: queued_voice_target_definition_id,
                generation: local_fanout_generation,
                route_kind,
                route_started_at: started_at,
                age_at_enqueue: ingress_age.saturating_add(started_at.elapsed()),
                enqueued_at: Instant::now(),
            })
            .await;
    } else {
        flush_voice_batch(server, audio, &targets).await;
        super::metrics::record_route(
            VoiceRouteSource::Local,
            route_kind,
            targets.len(),
            started_at.elapsed(),
        );
    }
}

pub(crate) async fn route_s2s_voice_frame(
    server: &Arc<Box<Server>>,
    from_immediate: crate::types::NodeIdentifier,
    frame: VoiceFrame,
) {
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
    route_decoded_s2s_voice_frame(server, from_immediate, frame, decoded).await;
}

/// Route an already decoded S2S voice frame to local recipients.
async fn route_decoded_s2s_voice_frame(
    server: &Arc<Box<Server>>,
    from_immediate: crate::types::NodeIdentifier,
    frame: VoiceFrame,
    decoded: Audio,
) {
    let started_at = Instant::now();
    let sender_id = crate::client::client_session_identifier::ClientSessionIdentifier::from(
        frame.sender_session,
    );

    let server_id = if frame.server_id.is_empty() {
        crate::types::default_server_id()
    } else {
        frame.server_id.clone()
    };
    let replicated_sender = server
        .get_clients()
        .get_client_in_server(&server_id, sender_id)
        .await;
    if replicated_sender.as_ref().is_some_and(client_voice_blocked) {
        return;
    }
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

    if replicated_sender.as_ref().is_some_and(client_voice_blocked) {
        return;
    }

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
    super::metrics::record_route_scope(VoiceRouteSource::S2s, voice_intent_scope(&intent));
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct VoiceTcpEgressTally {
    queued_packets: usize,
    queued_bytes: usize,
    dropped_packets: usize,
    dropped_bytes: usize,
    full_packets: usize,
    closed_packets: usize,
}

impl VoiceTcpEgressTally {
    fn from_enqueue_result(result: VoiceTcpEnqueueResult, bytes: usize) -> Self {
        let mut tally = Self::default();
        tally.record_enqueue_result(result, bytes);
        tally
    }

    fn record_enqueue_result(&mut self, result: VoiceTcpEnqueueResult, bytes: usize) {
        match result {
            VoiceTcpEnqueueResult::Accepted => {
                self.queued_packets += 1;
                self.queued_bytes += bytes;
            }
            VoiceTcpEnqueueResult::Full => {
                self.dropped_packets += 1;
                self.dropped_bytes += bytes;
                self.full_packets += 1;
            }
            VoiceTcpEnqueueResult::Closed => {
                self.dropped_packets += 1;
                self.dropped_bytes += bytes;
                self.closed_packets += 1;
            }
        }
    }

    fn merge(&mut self, other: Self) {
        self.queued_packets += other.queued_packets;
        self.queued_bytes += other.queued_bytes;
        self.dropped_packets += other.dropped_packets;
        self.dropped_bytes += other.dropped_bytes;
        self.full_packets += other.full_packets;
        self.closed_packets += other.closed_packets;
    }

    fn enqueue(&mut self, client: &Client, bytes: &Bytes) {
        if client.try_enqueue_voice_tcp(bytes.clone()) {
            self.record_enqueue_result(VoiceTcpEnqueueResult::Accepted, bytes.len());
        } else {
            self.record_enqueue_result(VoiceTcpEnqueueResult::Full, bytes.len());
        }
    }

    fn record_queue_outcomes(&self) {
        super::metrics::record_queue_enqueue_count(
            super::metrics::VoiceQueueKind::TcpFallback,
            super::metrics::VoiceQueueEnqueueResult::Accepted,
            self.queued_packets,
        );
        super::metrics::record_queue_enqueue_count(
            super::metrics::VoiceQueueKind::TcpFallback,
            super::metrics::VoiceQueueEnqueueResult::Full,
            self.full_packets,
        );
        super::metrics::record_queue_enqueue_count(
            super::metrics::VoiceQueueKind::TcpFallback,
            super::metrics::VoiceQueueEnqueueResult::Closed,
            self.closed_packets,
        );
        super::metrics::record_queue_drop_count(
            super::metrics::VoiceQueueDropReason::TcpQueueFull,
            self.full_packets,
        );
        super::metrics::record_queue_drop_count(
            super::metrics::VoiceQueueDropReason::TcpQueueClosed,
            self.closed_packets,
        );
    }

    fn record(&self) {
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

fn rayon_chunk_plan_for_udp_recipients(
    profile: VoiceDispatchProfile,
    udp_recipient_count: usize,
    rayon_workers: usize,
) -> Option<RayonChunkPlan> {
    if udp_recipient_count == 0 || !profile.uses_rayon(udp_recipient_count) {
        return None;
    }

    let chunk_plan = profile.rayon_chunk_plan(udp_recipient_count, rayon_workers);
    (chunk_plan.chunk_count() >= 2).then_some(chunk_plan)
}

fn rayon_chunk_plan_for_tcp_recipients(
    profile: VoiceDispatchProfile,
    tcp_recipient_count: usize,
    rayon_workers: usize,
) -> Option<RayonChunkPlan> {
    if tcp_recipient_count == 0 || !profile.uses_rayon(tcp_recipient_count) {
        return None;
    }

    let chunk_plan = profile.rayon_chunk_plan(tcp_recipient_count, rayon_workers);
    (chunk_plan.chunk_count() >= 2).then_some(chunk_plan)
}

/// Applies a recipient partition and aggregates its TCP enqueue outcomes.
/// Callers finish the entire partition before dispatching the next source
/// frame, which keeps every individual recipient's TCP queue FIFO.
fn tally_tcp_recipient_enqueues_sequential<T>(
    recipients: &[T],
    enqueue: &impl Fn(&T) -> VoiceTcpEgressTally,
) -> VoiceTcpEgressTally
where
    T: Sized,
{
    recipients
        .iter()
        .fold(VoiceTcpEgressTally::default(), |mut tally, recipient| {
            tally.merge(enqueue(recipient));
            tally
        })
}

fn tally_tcp_recipient_enqueues<T>(
    recipients: &[T],
    rayon_chunk_plan: Option<RayonChunkPlan>,
    enqueue: &(impl Fn(&T) -> VoiceTcpEgressTally + Sync),
) -> VoiceTcpEgressTally
where
    T: Sync,
{
    let Some(rayon_chunk_plan) = rayon_chunk_plan else {
        return tally_tcp_recipient_enqueues_sequential(recipients, enqueue);
    };

    use rayon::prelude::*;
    (0..rayon_chunk_plan.chunk_count())
        .into_par_iter()
        .map(|chunk_index| {
            tally_tcp_recipient_enqueues_sequential(
                &recipients[rayon_chunk_plan.range(chunk_index)],
                enqueue,
            )
        })
        .reduce(VoiceTcpEgressTally::default, |mut left, right| {
            left.merge(right);
            left
        })
}

type TcpVoiceRecipient = (Arc<Box<Client>>, Bytes);

fn enqueue_tcp_recipients(
    profile: VoiceDispatchProfile,
    recipients: Vec<TcpVoiceRecipient>,
) -> (VoiceTcpEgressTally, bool) {
    let rayon_chunk_plan = rayon_chunk_plan_for_tcp_recipients(
        profile,
        recipients.len(),
        rayon::current_num_threads(),
    );
    let enqueue = |(client, bytes): &TcpVoiceRecipient| {
        VoiceTcpEgressTally::from_enqueue_result(
            client.try_enqueue_voice_tcp_batched(bytes.clone()),
            bytes.len(),
        )
    };
    (
        tally_tcp_recipient_enqueues(&recipients, rayon_chunk_plan, &enqueue),
        rayon_chunk_plan.is_some(),
    )
}

fn encrypt_udp_recipients(
    recipients: &[UdpVoiceRecipient],
    plaintexts: &[VoicePlaintext],
    path: VoicePipelinePath,
) -> HashMap<std::net::SocketAddr, DatagramBatch> {
    let mut batches = HashMap::<std::net::SocketAddr, DatagramBatch>::new();
    for (client, local_addr, addr, format, context) in recipients {
        let Some(entry) = plaintexts
            .iter()
            .find_map(|(key, entry)| (*key == (*format, *context)).then_some(entry))
        else {
            continue;
        };
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
        let batch = batches
            .entry(*local_addr)
            .or_insert_with(DatagramBatch::new);
        let encrypt_started_at = Instant::now();
        let _ = batch.try_push_zeroed(*addr, encrypted_len, |buf| {
            state.encrypt_with_precomputed_checksum(buf, &entry.bytes, &entry.checksum)
        });
        super::metrics::record_pipeline_stage(
            path,
            VoicePipelineStage::UdpEncryptQueue,
            encrypt_started_at.elapsed(),
        );
    }
    batches
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
    let dispatch_profile = server
        .voice_dispatch_plan()
        .for_payload_len(audio.audio_payload.len());

    if !dispatch_profile.uses_rayon(targets.len()) {
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
            let Some(local_addr) = server.udp_local_addr_for_client(client) else {
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

    let path = VoicePipelinePath::LocalRayon;

    // Large-fanout path: bucket recipients while collecting unique
    // (format, context) keys, pre-encode each unique key once, then dispatch
    // the CPU-bound encryption and TCP queueing loops to rayon.
    let mut udp_items: Vec<UdpVoiceRecipient> = Vec::with_capacity(targets.len());
    let mut tcp_items: Vec<TcpVoiceRecipient> = Vec::with_capacity(targets.len());
    let mut cache = EncodeCache::new();

    for (client, context) in targets {
        let format = client_packet_format(client, server_protocol_version);
        let lookup_started_at = Instant::now();
        if client.prefers_tcp_tunnel() {
            record_pipeline_stage(path, VoicePipelineStage::RecipientLookup, lookup_started_at);
            let encode_started_at = Instant::now();
            let entry = cache.get_or_encode(audio, *context, format);
            record_pipeline_stage(path, VoicePipelineStage::Encode, encode_started_at);
            tcp_items.push((client.clone(), entry.bytes));
            continue;
        }
        match client.get_udp_address() {
            Some(addr) => {
                if let Some(local_addr) = server.udp_local_addr_for_client(client) {
                    record_pipeline_stage(
                        path,
                        VoicePipelineStage::RecipientLookup,
                        lookup_started_at,
                    );
                    let encode_started_at = Instant::now();
                    let _ = cache.get_or_encode(audio, *context, format);
                    record_pipeline_stage(path, VoicePipelineStage::Encode, encode_started_at);
                    udp_items.push((client.clone(), local_addr, addr, format, *context));
                } else {
                    record_pipeline_stage(
                        path,
                        VoicePipelineStage::RecipientLookup,
                        lookup_started_at,
                    );
                    let encode_started_at = Instant::now();
                    let entry = cache.get_or_encode(audio, *context, format);
                    record_pipeline_stage(path, VoicePipelineStage::Encode, encode_started_at);
                    tcp_items.push((client.clone(), entry.bytes));
                }
            }
            None => {
                record_pipeline_stage(path, VoicePipelineStage::RecipientLookup, lookup_started_at);
                let encode_started_at = Instant::now();
                let entry = cache.get_or_encode(audio, *context, format);
                record_pipeline_stage(path, VoicePipelineStage::Encode, encode_started_at);
                tcp_items.push((client.clone(), entry.bytes));
            }
        }
    }
    let tcp_enqueue_started_at = Instant::now();
    let (tcp_tally, tcp_used_rayon) = enqueue_tcp_recipients(dispatch_profile, tcp_items);
    if tcp_tally.queued_packets + tcp_tally.dropped_packets > 0 {
        record_pipeline_stage(path, VoicePipelineStage::TcpEnqueue, tcp_enqueue_started_at);
    }
    tcp_tally.record_queue_outcomes();
    tcp_tally.record();

    if udp_items.is_empty() {
        super::metrics::record_dispatch(if tcp_used_rayon {
            VoiceDispatchMode::Rayon
        } else {
            VoiceDispatchMode::Sequential
        });
        return;
    }

    // Snapshot the cache as a plain Vec for the rayon closure. The Vec is
    // moved into `spawn_blocking`; rayon workers only borrow it during the
    // scoped parallel iteration, so no Arc wrapper is needed here.
    let plaintexts: Vec<VoicePlaintext> = cache
        .slots
        .into_iter()
        .flatten()
        .chain(cache.overflow.into_iter())
        .collect();

    let (batches, udp_used_rayon): (HashMap<std::net::SocketAddr, DatagramBatch>, bool) =
        match rayon_chunk_plan_for_udp_recipients(
            dispatch_profile,
            udp_items.len(),
            rayon::current_num_threads(),
        ) {
            Some(rayon_chunk_plan) => {
                let rayon_started_at = Instant::now();
                let batches = tokio::task::spawn_blocking(move || {
                    use rayon::prelude::*;
                    let recipients = udp_items.as_slice();
                    (0..rayon_chunk_plan.chunk_count())
                        .into_par_iter()
                        .map(|chunk_index| {
                            encrypt_udp_recipients(
                                &recipients[rayon_chunk_plan.range(chunk_index)],
                                &plaintexts,
                                path,
                            )
                        })
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
                .unwrap_or_else(|error| {
                    tracing::warn!("voice encrypt task join error: {error}");
                    HashMap::new()
                });
                record_pipeline_stage(path, VoicePipelineStage::RayonEncryptJoin, rayon_started_at);
                (batches, true)
            }
            None => (
                encrypt_udp_recipients(&udp_items, &plaintexts, VoicePipelinePath::LocalSequential),
                false,
            ),
        };
    super::metrics::record_dispatch(if tcp_used_rayon || udp_used_rayon {
        VoiceDispatchMode::Rayon
    } else {
        VoiceDispatchMode::Sequential
    });

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
    let local_fanout_queue = Arc::new(LocalFanoutQueue::new());
    let fanout_server = server.clone();
    let fanout_queue = local_fanout_queue.clone();
    tokio::spawn(
        async move {
            while let Some(work) = fanout_queue.pop().await {
                let local_queue_age = work.enqueued_at.elapsed();
                let packet_age = work.age_at_enqueue.saturating_add(local_queue_age);
                super::metrics::record_packet_age(VoiceAgeStage::LocalFanoutQueue, packet_age);
                super::metrics::record_scheduler_delay(
                    VoiceSchedulerStage::LocalFanoutWorker,
                    local_queue_age,
                );
                if packet_age > fanout_server.read_config().voice.max_routing_queue_age() {
                    super::metrics::record_stale_drop(VoiceAgeStage::LocalFanoutQueue);
                    continue;
                }
                let Some(current_sender) = fanout_server
                    .get_clients()
                    .get_client_in_server(&work.server_id, work.sender_id)
                    .await
                else {
                    continue;
                };
                let current_generation = LocalFanoutGeneration::capture(
                    &fanout_server,
                    &current_sender,
                    &work.server_id,
                    current_sender.get_current_channel_id(),
                );
                if !local_fanout_snapshot_is_current(
                    work.sender_instance_id,
                    &work.generation,
                    work.route_kind,
                    Some((current_sender.client_instance_id(), &current_generation)),
                ) || !voice_target_definition_is_current(
                    work.route_kind,
                    work.voice_target_definition_id,
                    voice_target_definition_id(&current_sender, &work.audio.target),
                ) {
                    continue;
                }
                let targets = live_targets_from_local_fanout_snapshot(&work.targets);
                let Some(latest_sender) = fanout_server
                    .get_clients()
                    .get_client_in_server(&work.server_id, work.sender_id)
                    .await
                else {
                    continue;
                };
                let latest_generation = LocalFanoutGeneration::capture(
                    &fanout_server,
                    &latest_sender,
                    &work.server_id,
                    latest_sender.get_current_channel_id(),
                );
                if !local_fanout_snapshot_is_current(
                    work.sender_instance_id,
                    &work.generation,
                    work.route_kind,
                    Some((latest_sender.client_instance_id(), &latest_generation)),
                ) || !voice_target_definition_is_current(
                    work.route_kind,
                    work.voice_target_definition_id,
                    voice_target_definition_id(&latest_sender, &work.audio.target),
                ) {
                    continue;
                }
                if client_voice_blocked(&latest_sender) {
                    continue;
                }
                flush_voice_batch(&fanout_server, &work.audio, &targets).await;
                super::metrics::record_route(
                    VoiceRouteSource::Local,
                    work.route_kind,
                    targets.len(),
                    work.route_started_at.elapsed(),
                );
            }
        }
        .instrument(span.clone()),
    );
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
                route_voice_inner(
                    &server,
                    &sender,
                    payload.decoded_audio(),
                    queue_age,
                    Some(&local_fanout_queue),
                )
                .await;
            }
            local_fanout_queue.close();
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
                let message = shitspeak_messages::messages::Message::UDPTunnel(raw);
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

    #[test]
    fn rayon_dispatch_requires_enough_udp_recipients() {
        let profile =
            super::super::dispatch_tuning::VoiceDispatchPlan::conservative().for_payload_len(170);

        assert!(profile.uses_rayon(512));
        assert!(rayon_chunk_plan_for_udp_recipients(profile, 1, 8).is_none());
        assert!(rayon_chunk_plan_for_udp_recipients(profile, 511, 8).is_none());

        let chunk_plan = rayon_chunk_plan_for_udp_recipients(profile, 512, 8)
            .expect("threshold-sized UDP fan-out uses Rayon");
        assert_eq!(chunk_plan.chunk_count(), 2);
    }

    #[test]
    fn rayon_dispatch_uses_the_active_calibrated_breakpoint() {
        use super::super::dispatch_tuning::{RayonDispatchBreakpoint, VoiceDispatchProfile};

        let profile = VoiceDispatchProfile::from_breakpoints(&[
            RayonDispatchBreakpoint::new(512, 2, 256),
            RayonDispatchBreakpoint::new(1_024, 4, 512),
        ])
        .expect("valid dispatch schedule");

        assert!(rayon_chunk_plan_for_udp_recipients(profile, 511, 8).is_none());
        let low = rayon_chunk_plan_for_udp_recipients(profile, 512, 8)
            .expect("first breakpoint uses Rayon");
        assert_eq!((low.chunk_count(), low.chunk_len()), (2, 256));

        let high = rayon_chunk_plan_for_udp_recipients(profile, 2_048, 8)
            .expect("later breakpoint uses Rayon");
        assert_eq!((high.chunk_count(), high.chunk_len()), (4, 512));
    }

    #[test]
    fn parallel_tcp_enqueue_keeps_each_recipient_fifo_and_aggregates_outcomes() {
        const RECIPIENTS: usize = 512;
        const FRAMES: usize = 8;

        let profile =
            super::super::dispatch_tuning::VoiceDispatchPlan::conservative().for_payload_len(170);
        let chunk_plan = rayon_chunk_plan_for_tcp_recipients(profile, RECIPIENTS, 2)
            .expect("large TCP fan-out should use multiple chunks");
        assert_eq!(chunk_plan.chunk_count(), 2);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("test Rayon pool");
        let mut senders = Vec::with_capacity(RECIPIENTS);
        let mut receivers = Vec::with_capacity(RECIPIENTS);
        for _ in 0..RECIPIENTS {
            let (sender, receiver) = tokio::sync::mpsc::channel(FRAMES);
            senders.push(sender);
            receivers.push(receiver);
        }

        for frame in 0..FRAMES {
            let tally = pool.install(|| {
                let enqueue = |sender: &tokio::sync::mpsc::Sender<usize>| {
                    let result = match sender.try_send(frame) {
                        Ok(()) => VoiceTcpEnqueueResult::Accepted,
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            VoiceTcpEnqueueResult::Full
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            VoiceTcpEnqueueResult::Closed
                        }
                    };
                    VoiceTcpEgressTally::from_enqueue_result(result, 1)
                };
                tally_tcp_recipient_enqueues(&senders, Some(chunk_plan), &enqueue)
            });
            assert_eq!(tally.queued_packets, RECIPIENTS);
            assert_eq!(tally.queued_bytes, RECIPIENTS);
            assert_eq!(tally.dropped_packets, 0);
        }

        for receiver in &mut receivers {
            let delivered = (0..FRAMES)
                .map(|_| receiver.try_recv().expect("queued TCP frame"))
                .collect::<Vec<_>>();
            assert_eq!(delivered, (0..FRAMES).collect::<Vec<_>>());
        }
    }

    #[test]
    fn bounded_local_fanout_queue_evicts_oldest_and_retains_fifo_order() {
        let mut queue = VecDeque::new();
        for frame in 0..LOCAL_FANOUT_QUEUE_CAPACITY {
            assert!(matches!(
                push_bounded(&mut queue, LOCAL_FANOUT_QUEUE_CAPACITY, frame, |_| false,),
                BoundedPushResult::Accepted
            ));
        }

        assert!(matches!(
            push_bounded(
                &mut queue,
                LOCAL_FANOUT_QUEUE_CAPACITY,
                LOCAL_FANOUT_QUEUE_CAPACITY,
                |_| false,
            ),
            BoundedPushResult::EvictedNonTerminator
        ));
        assert_eq!(
            queue.into_iter().collect::<Vec<_>>(),
            (1..=LOCAL_FANOUT_QUEUE_CAPACITY).collect::<Vec<_>>()
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TestQueuedFrame {
        id: usize,
        terminator: bool,
    }

    #[test]
    fn bounded_local_fanout_queue_never_evicts_a_terminator() {
        let mut queue = VecDeque::from([
            TestQueuedFrame {
                id: 0,
                terminator: true,
            },
            TestQueuedFrame {
                id: 1,
                terminator: false,
            },
            TestQueuedFrame {
                id: 2,
                terminator: true,
            },
        ]);

        assert!(matches!(
            push_bounded(
                &mut queue,
                3,
                TestQueuedFrame {
                    id: 3,
                    terminator: false
                },
                |frame| frame.terminator,
            ),
            BoundedPushResult::EvictedNonTerminator
        ));
        assert_eq!(
            queue.iter().map(|frame| frame.id).collect::<Vec<_>>(),
            [0, 2, 3]
        );
        assert!(
            queue
                .iter()
                .filter(|frame| frame.terminator)
                .all(|frame| { frame.id == 0 || frame.id == 2 })
        );
    }

    #[test]
    fn all_terminator_queue_waits_for_space_without_mutation() {
        let mut queue = VecDeque::from([
            TestQueuedFrame {
                id: 0,
                terminator: true,
            },
            TestQueuedFrame {
                id: 1,
                terminator: true,
            },
        ]);

        let result = push_bounded(
            &mut queue,
            2,
            TestQueuedFrame {
                id: 2,
                terminator: true,
            },
            |frame| frame.terminator,
        );
        assert!(matches!(result, BoundedPushResult::NeedsSpace(_)));
        assert_eq!(
            queue.iter().map(|frame| frame.id).collect::<Vec<_>>(),
            [0, 1]
        );
    }

    #[test]
    fn local_fanout_generation_rejects_disconnect_move_and_acl_change() {
        let expected = LocalFanoutGeneration {
            channel_version: 1,
            channel_acl_generation: 2,
            voice_routing_generation: 3,
            sender_acl_generation: 4,
            sender_channel: 5,
        };
        assert!(!local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Normal,
            None,
        ));
        assert!(!local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Normal,
            Some((8, &expected)),
        ));

        let mut moved = LocalFanoutGeneration { ..expected };
        moved.sender_channel = 6;
        assert!(!local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Normal,
            Some((7, &moved))
        ));

        let mut acl_changed = LocalFanoutGeneration { ..expected };
        acl_changed.sender_acl_generation = 5;
        assert!(!local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Normal,
            Some((7, &acl_changed)),
        ));
        let mut channel_acl_changed = LocalFanoutGeneration { ..expected };
        channel_acl_changed.channel_acl_generation = 3;
        assert!(!local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Normal,
            Some((7, &channel_acl_changed)),
        ));
        assert!(local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Normal,
            Some((7, &expected)),
        ));
    }

    #[test]
    fn voice_target_fanout_generation_rejects_routing_and_channel_changes() {
        let expected = LocalFanoutGeneration {
            channel_version: 1,
            channel_acl_generation: 2,
            voice_routing_generation: 3,
            sender_acl_generation: 4,
            sender_channel: 5,
        };
        let mut channel_changed = LocalFanoutGeneration { ..expected };
        channel_changed.channel_version += 1;
        assert!(!local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Target,
            Some((7, &channel_changed)),
        ));

        let mut routing_changed = LocalFanoutGeneration { ..expected };
        routing_changed.voice_routing_generation += 1;
        assert!(!local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Target,
            Some((7, &routing_changed)),
        ));
        assert!(local_fanout_snapshot_is_current(
            7,
            &expected,
            VoiceRouteKind::Normal,
            Some((7, &routing_changed)),
        ));
    }

    #[test]
    fn voice_target_fanout_rejects_replaced_slot_definition() {
        assert!(voice_target_definition_is_current(
            VoiceRouteKind::Target,
            Some(10),
            Some(10),
        ));
        assert!(!voice_target_definition_is_current(
            VoiceRouteKind::Target,
            Some(10),
            Some(11),
        ));
        assert!(!voice_target_definition_is_current(
            VoiceRouteKind::Target,
            Some(10),
            None,
        ));
        assert!(voice_target_definition_is_current(
            VoiceRouteKind::Normal,
            None,
            None,
        ));
    }

    fn base_s2s_normal_cache_key() -> S2SVoiceNormalResolutionCacheKey {
        S2SVoiceNormalResolutionCacheKey {
            server_identity: 1,
            local_node_id: 2,
            server_id: "default".to_owned(),
            sender_session: ClientSessionIdentifier::from(0x0002_0001),
            sender_instance_id: Some(7),
            channel_version: 11,
            channel_acl_generation: 13,
            voice_routing_generation: 17,
            sender_acl_generation: 23,
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
        changed.voice_routing_generation += 1;
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.sender_acl_generation += 1;
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.hide_users_without_traverse = true;
        assert_ne!(base, changed);

        let mut changed = base.clone();
        changed.source_channel += 1;
        assert_ne!(base, changed);
    }

    #[test]
    fn s2s_scope_ignores_denied_whole_server_and_canonicalizes_channels() {
        let mut target = VoiceTarget::new();
        target.add_channel(crate::client::voice_target::VoiceTargetChannel::new(
            0,
            true,
            false,
            String::new(),
        ));
        target.add_channel(crate::client::voice_target::VoiceTargetChannel::new(
            7,
            true,
            false,
            String::new(),
        ));
        let authorized = [
            ResolvedVoiceTargetChannel::denied_like(&ResolvedVoiceTargetChannel::whole_server(
                String::new(),
            )),
            ResolvedVoiceTargetChannel::new(7, String::new(), false, vec![9, 7, 9]),
        ];

        let channels = s2s_target_channels(&target, &authorized).expect("channel scope");
        assert_eq!(channels.as_ref(), &[7, 9]);

        let intent = authorized_target_intent(3, &target, &authorized);
        let Some(VoiceIntentKind::Target(intent)) = intent.kind else {
            panic!("expected target intent");
        };
        assert_eq!(intent.channels.len(), 1);
        assert_eq!(intent.channels[0].id, 7);
    }

    #[test]
    fn authorized_whole_server_uses_server_scope() {
        let mut target = VoiceTarget::new();
        target.add_channel(crate::client::voice_target::VoiceTargetChannel::new(
            0,
            true,
            true,
            String::new(),
        ));

        let channels = s2s_target_channels(
            &target,
            &[ResolvedVoiceTargetChannel::whole_server(String::new())],
        )
        .expect("whole-server scope");
        assert!(channels.is_empty());
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
