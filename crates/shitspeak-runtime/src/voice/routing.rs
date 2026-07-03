//! Voice routing logic — determines recipients and dispatches audio packets.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use tracing::Instrument;

use super::codec::{self, Audio, PacketFormat};
use super::metrics::{
    VoiceDispatchMode, VoiceEgressResult, VoiceEgressTransport, VoiceRouteKind, VoiceRouteSource,
};
use super::routing_queue::VoiceRoutingPayload;
use super::udp_batch::{self, DatagramBatch};
use crate::{
    client::{
        Client, ClientInstanceId,
        client_session_identifier::ClientSessionIdentifier,
        crypt::CryptState,
        voice_target::{ResolvedVoiceTargetChannel, VoiceTarget},
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

    let (intent, target_kind, send_s2s, route_kind, resolved_channels) = match audio.target {
        AudioTarget::Normal => (
            normal_intent(sender_channel),
            S2S_TARGET_NORMAL,
            true,
            VoiceRouteKind::Normal,
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
            (
                target_intent(sender_channel, &vt),
                S2S_TARGET_SHOUT,
                true,
                VoiceRouteKind::Target,
                Some(resolved_channels),
            )
        }
    };

    let default_context = audio_context_from_target_kind(target_kind);
    let targets = resolve_voice_intent_with_resolved_channels(
        server,
        Some(sender),
        &server_id,
        sender_id,
        &intent,
        default_context,
        resolved_channels.as_deref(),
    )
    .await;

    tracing::trace!(
        session = u32::from(sender_id),
        channel = sender_channel,
        count = targets.len(),
        "resolved local voice recipients"
    );
    flush_voice_batch(server, audio, &targets).await;
    super::metrics::record_route(
        VoiceRouteSource::Local,
        route_kind,
        targets.len(),
        started_at.elapsed(),
    );

    if send_s2s {
        let payload = encode_s2s_voice_payload(audio);
        let is_terminator = matches!(
            &audio.audio_payload,
            codec::AudioPayload::Opus(payload) if payload.is_terminator
        );
        let sent = match intent.kind.as_ref() {
            Some(VoiceIntentKind::Normal(normal)) => server.s2s_manager().send_voice_for_channel(
                u32::from(sender_id),
                server_id.clone(),
                normal.source_channel,
                is_terminator,
                payload,
            ),
            _ => server.s2s_manager().send_voice_broadcast(
                u32::from(sender_id),
                server_id.clone(),
                target_kind,
                is_terminator,
                payload,
                intent,
            ),
        };
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

    let targets = resolve_voice_intent(
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
    flush_voice_batch(server, &decoded, &targets).await;
    super::metrics::record_route(
        VoiceRouteSource::S2s,
        route_kind,
        targets.len(),
        started_at.elapsed(),
    );
}

fn enqueue_voice_tcp_metric(client: &Client, bytes: &Bytes) {
    let queued = client.try_enqueue_voice_tcp(bytes.clone());
    let result = if queued {
        VoiceEgressResult::Queued
    } else {
        VoiceEgressResult::Dropped
    };
    super::metrics::record_egress(VoiceEgressTransport::TcpTunnel, result, 1, bytes.len());
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

    if targets.len() < RAYON_FANOUT_THRESHOLD {
        super::metrics::record_dispatch(VoiceDispatchMode::Sequential);
        let mut cache = EncodeCache::new();
        let mut udp_batches: HashMap<std::net::SocketAddr, DatagramBatch> = HashMap::new();

        for (client, context) in targets {
            let format = client_packet_format(client, server_protocol_version);
            let entry = cache.get_or_encode(audio, *context, format);

            if client.prefers_tcp_tunnel() {
                enqueue_voice_tcp_metric(client, &entry.bytes);
                continue;
            }

            let Some(addr) = client.get_udp_address() else {
                enqueue_voice_tcp_metric(client, &entry.bytes);
                continue;
            };
            let Some(local_addr) = server
                .udp_socket_for_client(client)
                .and_then(|socket| socket.local_addr().ok())
            else {
                enqueue_voice_tcp_metric(client, &entry.bytes);
                continue;
            };

            let mut crypt = client.crypt_state();
            let Some(state) = crypt.as_mut() else {
                continue;
            };
            let encrypted_len = entry.bytes.len() + state.overhead();
            let udp_batch = udp_batches
                .entry(local_addr)
                .or_insert_with(|| DatagramBatch::with_capacity(targets.len()));
            if udp_batch
                .try_push_zeroed(addr, encrypted_len, |buf| {
                    state.encrypt_with_precomputed_checksum(buf, &entry.bytes, &entry.checksum)
                })
                .is_err()
            {
                tracing::trace!(
                    session = u32::from(client.get_session_id()),
                    "encryption failed for client, falling back to TCP tunnel"
                );
                enqueue_voice_tcp_metric(client, &entry.bytes);
                continue;
            }
        }

        for (local_addr, udp_batch) in udp_batches {
            if udp_batch.is_empty() {
                continue;
            }
            let packet_count = udp_batch.len();
            let byte_count = udp_batch.bytes_len();
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
            if let Err(e) = udp_batch::flush_batch(socket.as_ref(), &udp_batch).await {
                tracing::warn!("UDP batch send error: {e}");
                super::metrics::record_egress(
                    VoiceEgressTransport::Udp,
                    VoiceEgressResult::Failed,
                    packet_count,
                    byte_count,
                );
            } else {
                super::metrics::record_egress(
                    VoiceEgressTransport::Udp,
                    VoiceEgressResult::Sent,
                    packet_count,
                    byte_count,
                );
            }
        }
        return;
    }

    super::metrics::record_dispatch(VoiceDispatchMode::Rayon);

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
        let _ = cache.get_or_encode(audio, *context, format);

        if client.prefers_tcp_tunnel() {
            tcp_items.push((client.clone(), format, *context));
            continue;
        }
        match client.get_udp_address() {
            Some(addr) => {
                if let Some(local_addr) = server
                    .udp_socket_for_client(client)
                    .and_then(|socket| socket.local_addr().ok())
                {
                    udp_items.push((client.clone(), local_addr, addr, format, *context));
                } else {
                    tcp_items.push((client.clone(), format, *context));
                }
            }
            None => tcp_items.push((client.clone(), format, *context)),
        }
    }

    // TCP fallback recipients — enqueue using the cached plaintext, do not await.
    for (client, format, context) in &tcp_items {
        let entry = cache.get_or_encode(audio, *context, *format);
        enqueue_voice_tcp_metric(client, &entry.bytes);
    }

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
                        let mut crypt = client.crypt_state();
                        let Some(state) = crypt.as_mut() else {
                            return batches;
                        };
                        let encrypted_len = entry.bytes.len() + state.overhead();
                        let batch = batches.entry(local_addr).or_insert_with(DatagramBatch::new);
                        let _ = batch.try_push_zeroed(addr, encrypted_len, |buf| {
                            state.encrypt_with_precomputed_checksum(
                                buf,
                                &entry.bytes,
                                &entry.checksum,
                            )
                        });
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

    for (local_addr, batch) in batches {
        if batch.is_empty() {
            continue;
        }
        let packet_count = batch.len();
        let byte_count = batch.bytes_len();
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
        if let Err(e) = udp_batch::flush_batch(socket.as_ref(), &batch).await {
            tracing::warn!("UDP batch send error: {e}");
            super::metrics::record_egress(
                VoiceEgressTransport::Udp,
                VoiceEgressResult::Failed,
                packet_count,
                byte_count,
            );
        } else {
            super::metrics::record_egress(
                VoiceEgressTransport::Udp,
                VoiceEgressResult::Sent,
                packet_count,
                byte_count,
            );
        }
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
                route_voice(&server, &sender, &payload.decoded_audio).await;
            }
        }
        .instrument(span),
    );
}

/// Spawn a per-user voice TCP send task.
///
/// Drains the per-user `voice_tcp` queue and writes each `UDPTunnel` payload
/// to the TLS stream serially.  Decouples the routing fan-out from
/// per-recipient TCP backpressure: if a recipient's TLS write is slow,
/// only their own queue backs up (and ultimately drops), other recipients
/// in the same fan-out are unaffected.
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
