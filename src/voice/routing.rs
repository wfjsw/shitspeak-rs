//! Voice routing logic — determines recipients and dispatches audio packets.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use super::codec::{self, Audio, PacketFormat};
use super::routing_queue::VoiceRoutingPayload;
use super::udp_batch::{self, DatagramBatch};
use crate::{
    client::{Client, crypt::CryptState},
    constants::PROTOBUF_INTRODUCED_VERSION,
    messages::encoder::{Audio as AudioWire, AudioContext, AudioHeader, AudioTarget},
    s2s::application::proto::{
        VoiceFrame, VoiceIntent, VoiceIntentKind, VoiceIntentNormal, VoiceIntentTarget,
        VoiceTargetChannel as S2SVoiceTargetChannel,
    },
    server::Server,
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

fn client_matches_voice_target_group(
    client: &Arc<Box<Client>>,
    source_channel: u32,
    target_channel: u32,
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
    let membership = crate::client::group::ClientMembershipQuery {
        groups: &group_refs,
        authenticated: client.get_user_id().is_some(),
        access_tokens: &token_refs,
        cert_hash: client.get_certificate_hash(),
        has_verified_cert_chain: client.is_verified(),
        ip_address: Some(client.get_real_ip_address()),
        asn: None,
        country_code: None,
    };
    crate::client::group::is_member_in_group(
        group,
        source_channel,
        Some(target_channel),
        &[],
        &membership,
    )
}

fn push_unique_target(
    targets: &mut Vec<(Arc<Box<Client>>, AudioContext)>,
    seen: &mut HashSet<(u32, AudioContext)>,
    sender_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    client: Arc<Box<Client>>,
    context: AudioContext,
) {
    if client.get_session_id() == sender_id || !client.is_authenticated() {
        return;
    }
    if !client.read_local_state().is_some() {
        return;
    }
    if seen.insert((u32::from(client.get_session_id()), context)) {
        targets.push((client, context));
    }
}

async fn resolve_voice_intent(
    server: &Arc<Box<Server>>,
    sender: Option<&Arc<Box<Client>>>,
    server_id: &str,
    sender_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    intent: &VoiceIntent,
    default_context: AudioContext,
) -> Vec<(Arc<Box<Client>>, AudioContext)> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let local_node_id = server.get_clients().local_node_id();

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
                        client,
                        AudioContext::Whisper,
                    );
                }
            }

            for ch_target in &target.channels {
                let mut channel_ids = if ch_target.children {
                    collect_subtree_ids(server, server_id, ch_target.id).await
                } else {
                    vec![ch_target.id]
                };

                if ch_target.links {
                    let mut linked_ids = Vec::new();
                    for &ch_id in &channel_ids {
                        if let Some(group) = server
                            .get_channels()
                            .effective_link_group_in_server(server_id, ch_id)
                        {
                            for &linked_id in group.iter() {
                                if !channel_ids.contains(&linked_id)
                                    && !linked_ids.contains(&linked_id)
                                {
                                    linked_ids.push(linked_id);
                                }
                            }
                        }
                    }
                    channel_ids.extend(linked_ids);
                }

                if let Some(sender) = sender {
                    let mut allowed_channels = Vec::new();
                    for channel_id in channel_ids {
                        let perms = crate::client::acl::compute_permissions_for_client(
                            server, sender, channel_id,
                        )
                        .await;
                        if perms.contains(crate::acl::ACLPermissions::Whisper) {
                            allowed_channels.push(channel_id);
                        }
                    }
                    channel_ids = allowed_channels;
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
                    if !channel_ids.contains(&client_channel) {
                        continue;
                    }
                    if !client_matches_voice_target_group(
                        &client,
                        target.source_channel,
                        client_channel,
                        &ch_target.group,
                    ) {
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
                        client,
                        AudioContext::Shout,
                    );
                }

                let channel_listeners = server
                    .get_clients()
                    .get_local_listeners_for_channels_in_server(server_id, &channel_ids)
                    .await;
                for client in channel_listeners {
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
                    sender.clone(),
                    default_context,
                );
            }
        }
    }

    targets
}

pub async fn route_voice(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, audio: &Audio) {
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

    let (intent, target_kind, send_s2s) = match audio.target {
        AudioTarget::Normal => (normal_intent(sender_channel), S2S_TARGET_NORMAL, true),
        AudioTarget::ServerLoopback => {
            let targets = vec![(sender.clone(), AudioContext::Normal)];
            flush_voice_batch(server, audio, &targets).await;
            return;
        }
        AudioTarget::VoiceTarget(slot) => {
            let udp_state = sender.udp_state().await;
            let Some(vt) = udp_state.voice_target(slot).cloned() else {
                return;
            };
            if vt.is_empty() {
                return;
            }
            (target_intent(sender_channel, &vt), S2S_TARGET_SHOUT, true)
        }
    };

    let default_context = audio_context_from_target_kind(target_kind);
    let targets = resolve_voice_intent(
        server,
        Some(sender),
        &server_id,
        sender_id,
        &intent,
        default_context,
    )
    .await;

    tracing::trace!(
        session = u32::from(sender_id),
        channel = sender_channel,
        count = targets.len(),
        "resolved local voice recipients"
    );
    flush_voice_batch(server, audio, &targets).await;

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
    let intent = match frame.intent.clone() {
        Some(intent) => intent,
        None => {
            let source_channel = replicated_sender
                .as_ref()
                .map(|client| client.get_current_channel_id())
                .unwrap_or(0);
            normal_intent(source_channel)
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
        let mut cache = EncodeCache::new();
        let mut udp_batches: HashMap<std::net::SocketAddr, DatagramBatch> = HashMap::new();

        for (client, context) in targets {
            let format = client_packet_format(client, server_protocol_version);
            let entry = cache.get_or_encode(audio, *context, format);

            if client.prefers_tcp_tunnel() {
                client.try_enqueue_voice_tcp(entry.bytes);
                continue;
            }

            let Some(addr) = client.get_udp_address() else {
                client.try_enqueue_voice_tcp(entry.bytes);
                continue;
            };
            let Some(local_addr) = server
                .udp_socket_for_client(client)
                .and_then(|socket| socket.local_addr().ok())
            else {
                client.try_enqueue_voice_tcp(entry.bytes);
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
                client.try_enqueue_voice_tcp(entry.bytes);
                continue;
            }
        }

        for (local_addr, udp_batch) in udp_batches {
            if udp_batch.is_empty() {
                continue;
            }
            let Some(socket) = server.udp_socket_for_client_addr(local_addr) else {
                tracing::warn!(%local_addr, "UDP batch has no matching local socket");
                continue;
            };
            if let Err(e) = udp_batch::flush_batch(socket.as_ref(), &udp_batch).await {
                tracing::warn!("UDP batch send error: {e}");
            }
        }
        return;
    }

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
        client.try_enqueue_voice_tcp(entry.bytes);
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
        let Some(socket) = server.udp_socket_for_client_addr(local_addr) else {
            tracing::warn!(%local_addr, "UDP batch has no matching local socket");
            continue;
        };
        if let Err(e) = udp_batch::flush_batch(socket.as_ref(), &batch).await {
            tracing::warn!("UDP batch send error: {e}");
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
    let mut rx = match sender.take_voice_routing_rx() {
        Some(rx) => rx,
        None => {
            tracing::warn!(
                session = u32::from(sender.get_session_id()),
                "voice routing task already spawned"
            );
            return;
        }
    };
    let weak_sender = Arc::downgrade(&sender);
    tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            let Some(sender) = weak_sender.upgrade() else {
                break;
            };
            route_voice(&server, &sender, &payload.decoded_audio).await;
        }
    });
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
    let mut rx = match client.take_voice_tcp_rx() {
        Some(rx) => rx,
        None => {
            tracing::warn!(
                session = u32::from(client.get_session_id()),
                "voice TCP send task already spawned"
            );
            return;
        }
    };
    let weak_client = Arc::downgrade(&client);
    tokio::spawn(async move {
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
    });
}

/// Collect all channel IDs in the subtree rooted at `root_id`.
async fn collect_subtree_ids(server: &Arc<Box<Server>>, server_id: &str, root_id: u32) -> Vec<u32> {
    let all_channels = server.get_channels().get_all_in_server(server_id).await;
    let mut result = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root_id);
    while let Some(id) = queue.pop_front() {
        result.push(id);
        for ch in all_channels.iter().filter(|c| c.parent_id == Some(id)) {
            queue.push_back(ch.id);
        }
    }
    result
}
