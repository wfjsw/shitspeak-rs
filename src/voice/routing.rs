//! Voice routing logic — determines recipients and dispatches audio packets.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use super::codec::{self, Audio, PacketFormat};
use super::routing_queue::VoiceRoutingPayload;
use super::udp_batch::{self, QueuedDatagram};
use crate::{
    client::{crypt::CryptState, Client},
    constants::PROTOBUF_INTRODUCED_VERSION,
    messages::encoder::{Audio as AudioWire, AudioContext, AudioHeader, AudioTarget},
    server::Server,
};

/// Recipient count above which the encrypt fan-out is dispatched to rayon
/// inside `spawn_blocking`. Below this threshold, sequential per-recipient
/// encrypt on the routing task is faster: the per-recipient unit of work
/// (~600 ns at 170-byte packet) is too small to amortize rayon's task
/// scheduling overhead. Measured crossover on a Ryzen 7 5800H is ~256.
const RAYON_FANOUT_THRESHOLD: usize = 256;

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

/// `target_kind` value used in the S2S envelope for normal channel
/// speech. Mirrors the Mumble `AudioContext::NORMAL` numbering.
const S2S_TARGET_NORMAL: u32 = 0;

pub async fn route_voice(server: &Arc<Box<Server>>, sender: &Arc<Box<Client>>, audio: &Audio) {
    let sender_id = sender.get_session_id();
    let sender_channel = sender.get_current_channel_id();

    // Check if sender is muted/suppressed
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

    let target = audio.target;

    tracing::trace!(
        session = u32::from(sender_id),
        channel = sender_channel,
        target = %target,
        "routing voice packet"
    );

    // Collect (client, context) pairs for batched sending. The audio payload
    // is shared via the `outgoing` Arc.
    let mut targets: Vec<(Arc<Box<Client>>, AudioContext)> = Vec::new();

    // Pre-encoded payload for cross-node delivery (NORMAL channel speech
    // only). Receivers decode and re-target per local recipient, so we
    // encode with the speaker's chosen format and Normal context.
    let mut s2s_payload: Option<bytes::Bytes> = None;

    match target {
        AudioTarget::Normal => {
            tracing::trace!(
                session = u32::from(sender_id),
                channel = sender_channel,
                "routing normal channel speech"
            );

            s2s_payload = Some(encode_s2s_voice_payload(audio));

            // ── Normal speech: channel members (local only) ─────────────
            // Remote clients in the same channel are reached via S2S
            // delivery, not by direct UDP/TCP from this node.
            let channel_clients = server
                .get_clients()
                .get_local_clients_in_channel(sender_channel)
                .await;
            for client in &channel_clients {
                if client.get_session_id() == sender_id {
                    continue;
                }
                if !client.is_authenticated() {
                    continue;
                }
                targets.push((client.clone(), AudioContext::Normal));
            }

            // ── Normal speech: linked channels (local only) ─────────────
            // Voice fans out to members of channels linked to the sender's
            // channel. Per Mumble's reference behavior, the speaker must
            // hold Speak on the linked channel for voice to cross.
            let linked_ids: Vec<u32> = server
                .get_channels()
                .get_channel(sender_channel)
                .await
                .map(|ch| ch.links.into_iter().collect())
                .unwrap_or_default();
            for linked_id in linked_ids {
                let perms =
                    crate::client::acl::compute_permissions_for_client(server, sender, linked_id)
                        .await;
                if !perms.contains(crate::acl::ACLPermissions::Speak) {
                    continue;
                }
                let linked_clients = server
                    .get_clients()
                    .get_local_clients_in_channel(linked_id)
                    .await;
                for client in &linked_clients {
                    if client.get_session_id() == sender_id {
                        continue;
                    }
                    if !client.is_authenticated() {
                        continue;
                    }
                    targets.push((client.clone(), AudioContext::Normal));
                }
            }

            // ── Normal speech: cross-channel listeners (local only) ─────
            let listeners = server
                .get_clients()
                .get_local_listeners_for_channel(sender_channel)
                .await;
            for client in &listeners {
                if client.get_session_id() == sender_id {
                    continue;
                }
                if !client.is_authenticated() {
                    continue;
                }
                targets.push((client.clone(), AudioContext::Listen));
            }

            tracing::trace!(
                session = u32::from(sender_id),
                channel = sender_channel,
                count = targets.len(),
                "resolved recipients for normal channel speech"
            );
        }
        AudioTarget::ServerLoopback => {
            tracing::trace!(
                session = u32::from(sender_id),
                channel = sender_channel,
                "routing server loopback (target=31)"
            );
            targets.push((sender.clone(), AudioContext::Normal));
        }
        AudioTarget::VoiceTarget(slot) => {
            // ── Whisper/shout target ─────────────────────────────────────
            let udp_state = sender.udp_state().await;
            let voice_target = udp_state.voice_target(slot);

            if let Some(vt) = voice_target {
                tracing::trace!(
                    session = u32::from(sender_id),
                    channel = sender_channel,
                    slot,
                    "resolving whisper/shout recipients"
                );

                // Direct session targets — only deliver to local sessions
                // on this node. Remote whisper recipients must be reached
                // via S2S (deferred to a later phase).
                let local_node_id = server.get_clients().local_node_id();
                for session_raw in vt.sessions() {
                    let session_id =
                        crate::client::client_session_identifier::ClientSessionIdentifier::from(
                            *session_raw,
                        );
                    if session_id.node_id != local_node_id {
                        continue;
                    }
                    if let Some(client) = server.get_clients().get_client(session_id).await {
                        if client.is_authenticated() {
                            targets.push((client, AudioContext::Whisper));
                        }
                    }
                }

                // Channel targets — use the index for each target channel subtree
                for ch_target in vt.channels() {
                    let mut channel_ids = if ch_target.sub_channels() {
                        collect_subtree_ids(server, ch_target.id()).await
                    } else {
                        vec![ch_target.id()]
                    };

                    // Expand with linked channels when the links flag is set.
                    if ch_target.links() {
                        let mut linked_ids: Vec<u32> = Vec::new();
                        for &ch_id in &channel_ids {
                            if let Some(ch) = server.get_channels().get_channel(ch_id).await {
                                for linked_id in ch.links {
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

                    let channel_clients = server
                        .get_clients()
                        .get_local_clients_in_channels(&channel_ids)
                        .await;
                    for client in &channel_clients {
                        if client.get_session_id() == sender_id {
                            continue;
                        }
                        if !client.is_authenticated() {
                            continue;
                        }
                        targets.push((client.clone(), AudioContext::Shout));
                    }

                    // Listeners for all resolved channels receive the audio
                    // with Listen context, matching Normal speech behaviour.
                    let channel_listeners = server
                        .get_clients()
                        .get_local_listeners_for_channels(&channel_ids)
                        .await;
                    for client in &channel_listeners {
                        if client.get_session_id() == sender_id {
                            continue;
                        }
                        if !client.is_authenticated() {
                            continue;
                        }
                        targets.push((client.clone(), AudioContext::Listen));
                    }
                }
            }
        }
    }

    // ── Flush all targets locally ────────────────────────────────────────
    flush_voice_batch(server, audio, &targets).await;

    // ── Cross-node delivery (NORMAL channel speech only for now) ─────────
    if let Some(payload) = s2s_payload {
        if let Some(app) = server.s2s_manager().application() {
            let result = app
                .voice()
                .send_for_channel(
                    u32::from(sender_id),
                    sender_channel,
                    matches!(
                        &audio.audio_payload,
                        codec::AudioPayload::Opus(payload) if payload.is_terminator
                    ),
                    payload,
                )
                .await;
            if let Err(e) = result {
                tracing::trace!(error=%e, "voice s2s send failed");
            }
        }
    }
}

pub(crate) async fn route_s2s_voice_frame(
    server: &Arc<Box<Server>>,
    from_immediate: crate::types::NodeIdentifier,
    frame: crate::s2s::application::proto::VoiceFrame,
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

    let sender_channel = server
        .get_clients()
        .get_client(sender_id)
        .await
        .map(|client| client.get_current_channel_id())
        .unwrap_or(0);

    let mut targets: Vec<(Arc<Box<Client>>, AudioContext)> = Vec::new();
    let channel_clients = server
        .get_clients()
        .get_local_clients_in_channel(sender_channel)
        .await;
    for client in &channel_clients {
        if client.get_session_id() == sender_id || !client.is_authenticated() {
            continue;
        }
        targets.push((client.clone(), AudioContext::Normal));
    }

    let listeners = server
        .get_clients()
        .get_local_listeners_for_channel(sender_channel)
        .await;
    for client in &listeners {
        if client.get_session_id() == sender_id || !client.is_authenticated() {
            continue;
        }
        targets.push((client.clone(), AudioContext::Listen));
    }

    tracing::trace!(
        from = from_immediate,
        sender = frame.sender_session,
        channel = sender_channel,
        count = targets.len(),
        "routing s2s normal voice frame to local recipients"
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
        let mut udp_batch: Vec<QueuedDatagram> = Vec::with_capacity(targets.len());

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

            let mut crypt = client.crypt_state();
            let Some(state) = crypt.as_mut() else {
                continue;
            };
            let mut buf = BytesMut::zeroed(entry.bytes.len() + state.overhead());
            if state
                .encrypt_with_precomputed_checksum(&mut buf, &entry.bytes, &entry.checksum)
                .is_err()
            {
                tracing::trace!(
                    session = u32::from(client.get_session_id()),
                    "encryption failed for client, falling back to TCP tunnel"
                );
                client.try_enqueue_voice_tcp(entry.bytes);
                continue;
            }
            udp_batch.push(QueuedDatagram {
                addr,
                data: buf.freeze(),
            });
        }

        if !udp_batch.is_empty() {
            let socket = server.get_udp_socket();
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
            Some(addr) => udp_items.push((client.clone(), addr, format, *context)),
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

    // Snapshot the cache as a plain Vec for the rayon closure (Send + Sync).
    let plaintexts: Arc<Vec<((PacketFormat, AudioContext), Encoded)>> = Arc::new(
        cache
            .slots
            .into_iter()
            .flatten()
            .chain(cache.overflow.into_iter())
            .collect(),
    );

    let plaintexts_for_task = plaintexts.clone();
    let batch: Vec<QueuedDatagram> = tokio::task::spawn_blocking(move || {
        use rayon::prelude::*;
        udp_items
            .into_par_iter()
            .filter_map(|(client, addr, format, context)| {
                let entry = plaintexts_for_task
                    .iter()
                    .find_map(|(k, e)| (*k == (format, context)).then(|| e.clone()))?;
                let mut crypt = client.crypt_state();
                let state = crypt.as_mut()?;
                let mut buf = BytesMut::zeroed(entry.bytes.len() + state.overhead());
                state
                    .encrypt_with_precomputed_checksum(&mut buf, &entry.bytes, &entry.checksum)
                    .ok()?;
                Some(QueuedDatagram {
                    addr,
                    data: buf.freeze(),
                })
            })
            .collect()
    })
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("voice encrypt task join error: {e}");
        Vec::new()
    });

    if !batch.is_empty() {
        let socket = server.get_udp_socket();
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
async fn collect_subtree_ids(server: &Arc<Box<Server>>, root_id: u32) -> Vec<u32> {
    let all_channels = server.get_channels().get_all().await;
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
