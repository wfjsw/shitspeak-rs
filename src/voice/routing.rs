//! Voice routing logic — determines recipients and dispatches audio packets.

use std::sync::Arc;

use crate::{
    client::Client,
    server::Server,
};

use super::codec::{self, DecodedAudio, PacketFormat};
use super::routing_queue::VoiceRoutingPayload;
use super::udp_batch::{self, QueuedDatagram};

/// `target_kind` value used in the S2S envelope for normal channel
/// speech. Mirrors the Mumble `AudioContext::NORMAL` numbering.
const S2S_TARGET_NORMAL: u32 = 0;

pub async fn route_voice(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    audio: &DecodedAudio,
    is_udp: bool,
) {
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
        target,
        is_udp,
        "routing voice packet"
    );

    // Build the outgoing audio data (server → client format) and share it
    // across recipients via Arc — only the per-recipient target context
    // differs, so we avoid cloning the full struct (and the positional_data
    // Vec when present) for every listener.
    let outgoing = Arc::new(DecodedAudio {
        target: 0, // unused — target is passed separately per recipient
        sender_session: u32::from(sender_id),
        frame_number: audio.frame_number,
        opus_data: audio.opus_data.clone(),
        positional_data: audio.positional_data.clone(),
        volume_adjustment: 0.0,
        is_terminator: audio.is_terminator,
        format: audio.format,
    });

    // Collect (client, target_context) pairs for batched sending. The audio
    // payload is shared via the `outgoing` Arc.
    let mut targets: Vec<(Arc<Box<Client>>, u32)> = Vec::new();

    // Pre-encoded payload for cross-node delivery (NORMAL channel speech
    // only). Receivers decode and re-target per local recipient, so we
    // encode with the speaker's chosen format and `target = 0`.
    let mut s2s_payload: Option<bytes::Bytes> = None;

    if target == 0 {
        tracing::trace!(
            session = u32::from(sender_id),
            channel = sender_channel,
            "routing normal channel speech"
        );

        s2s_payload = Some(codec::encode_audio_packet(&outgoing, 0, audio.format));

        // ── Normal speech: channel members (local only) ─────────────────
        // Remote clients in the same channel are reached via S2S delivery,
        // not by direct UDP/TCP from this node.
        let channel_clients = server.get_clients().get_local_clients_in_channel(sender_channel).await;
        for client in &channel_clients {
            if client.get_session_id() == sender_id {
                continue;
            }
            if !client.is_authenticated() {
                continue;
            }
            targets.push((client.clone(), 0)); // AudioContext::NORMAL
        }

        // ── Normal speech: cross-channel listeners (local only) ─────────
        let listeners = server.get_clients().get_local_listeners_for_channel(sender_channel).await;
        for client in &listeners {
            if client.get_session_id() == sender_id {
                continue;
            }
            if !client.is_authenticated() {
                continue;
            }
            targets.push((client.clone(), 3)); // AudioContext::LISTEN
        }

        tracing::trace!(
            session = u32::from(sender_id),
            channel = sender_channel,
            target,
            count = targets.len(),
            "resolved recipients for normal channel speech"
         );
    } else if target == 0x1F {
        // ── Server loopback (target = 31) ────────────────────────────────
        tracing::trace!(
            session = u32::from(sender_id),
            channel = sender_channel,
            target,
            "routing server loopback (target=31)"
         );
        targets.push((sender.clone(), 0)); // AudioContext::NORMAL
    } else {
        // ── Whisper/shout target ─────────────────────────────────────────
        let udp_state = sender.udp_state().await;
        let voice_target = udp_state.voice_target(target);

        if let Some(vt) = voice_target {
            tracing::trace!(
                session = u32::from(sender_id),
                channel = sender_channel,
                target,
                "resolving whisper/shout recipients"
             );

            // Direct session targets — only deliver to local sessions on
            // this node.  Remote whisper recipients must be reached via
            // S2S (deferred to a later phase).
            let local_node_id = server.get_clients().local_node_id();
            for session_raw in vt.sessions() {
                let session_id =
                    crate::client::client_session_identifier::ClientSessionIdentifier::from(*session_raw);
                if session_id.node_id != local_node_id {
                    continue;
                }
                if let Some(client) = server.get_clients().get_client(session_id).await {
                    if client.is_authenticated() {
                        targets.push((client, 2)); // AudioContext::WHISPER
                    }
                }
            }

            // Channel targets — use the index for each target channel subtree
            for ch_target in vt.channels() {
                let channel_ids = if ch_target.sub_channels() {
                    collect_subtree_ids(server, ch_target.id()).await
                } else {
                    vec![ch_target.id()]
                };

                let channel_clients = server.get_clients().get_local_clients_in_channels(&channel_ids).await;
                for client in &channel_clients {
                    if client.get_session_id() == sender_id {
                        continue;
                    }
                    if !client.is_authenticated() {
                        continue;
                    }
                    targets.push((client.clone(), 1)); // AudioContext::SHOUT
                }
            }
        }
    }

    // ── Flush all targets locally ────────────────────────────────────────
    flush_voice_batch(server, &outgoing, &targets, is_udp).await;

    // ── Cross-node delivery (NORMAL channel speech only for now) ─────────
    // if let Some(payload) = s2s_payload {
    //     if let Some(app) = server.s2s_manager().application() {
    //         let voice = app.voice().clone();
    //         let _ = S2S_TARGET_NORMAL; // currently encoded inside send_for_channel
    //         let result = voice
    //             .send_for_channel(
    //                 u32::from(sender_id),
    //                 sender_channel,
    //                 audio.is_terminator,
    //                 payload,
    //             )
    //             .await;
    //         if let Err(e) = result {
    //             tracing::trace!(error=%e, "voice s2s send failed");
    //         }
    //     }
    // }
}

async fn flush_voice_batch(
    server: &Arc<Box<Server>>,
    audio: &Arc<DecodedAudio>,
    targets: &[(Arc<Box<Client>>, u32)],
    is_udp: bool,
) {
    if targets.is_empty() {
        return;
    }

    if is_udp {
        // Bucket targets: those reachable via UDP (encrypt + batch) vs. those
        // that must fall back to the TCP tunnel (no UDP address known yet, or
        // client has explicitly switched to tunneled mode).
        let mut udp_items: Vec<(Arc<Box<Client>>, std::net::SocketAddr, PacketFormat, u32)> =
            Vec::with_capacity(targets.len());
        let mut tcp_items: Vec<(Arc<Box<Client>>, PacketFormat, u32)> = Vec::new();

        for (client, target) in targets {
            let format = if client.read_global_state().uses_protobuf() {
                PacketFormat::Protobuf
            } else {
                PacketFormat::Legacy
            };

            if client.prefers_tcp_tunnel() {
                tcp_items.push((client.clone(), format, *target));
                continue;
            }

            match client.get_udp_address() {
                Some(addr) => udp_items.push((client.clone(), addr, format, *target)),
                None => tcp_items.push((client.clone(), format, *target)),
            }
        }

        // ── TCP-fallback recipients: enqueue, do not await ───────────────────
        for (client, format, target) in tcp_items {
            let raw = codec::encode_audio_packet(audio, target, format);
            client.try_enqueue_voice_tcp(raw);
        }

        // ── Parallel encode + encrypt for UDP-reachable recipients ───────────
        // Each recipient owns its own `CryptState` (parking_lot mutex), so
        // different recipients can encrypt concurrently.  We hand the entire
        // bucket to `spawn_blocking` and use rayon's work-stealing pool inside
        // for the actual parallelism — this keeps the reactor thread free while
        // the CPU work is in flight.
        let batch: Vec<QueuedDatagram> = if udp_items.is_empty() {
            Vec::new()
        } else {
            let audio_for_encode = audio.clone();
            tokio::task::spawn_blocking(move || {
                use rayon::prelude::*;
                udp_items
                    .into_par_iter()
                    .filter_map(|(client, addr, format, target)| {
                        let raw = codec::encode_audio_packet(&audio_for_encode, target, format);
                        let mut crypt = client.crypt_state();
                        let state = crypt.as_mut()?;
                        let mut buf = vec![0u8; raw.len() + state.overhead()];
                        state.encrypt(&mut buf, &raw).ok()?;
                        Some(QueuedDatagram {
                            addr,
                            data: bytes::Bytes::from(buf),
                        })
                    })
                    .collect()
            })
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("voice encrypt task join error: {e}");
                Vec::new()
            })
        };

        if !batch.is_empty() {
            let socket = server.get_udp_socket();
            if let Err(e) = udp_batch::flush_batch(socket.as_ref(), &batch).await {
                tracing::warn!("UDP batch send error: {e}");
            }
        }
    } else {
        // TCP tunnel path — encode and enqueue per recipient.  The per-user
        // TCP send task drains the queue and writes serially to the TLS stream.
        for (client, target) in targets {
            let format = if client.read_global_state().uses_protobuf() {
                PacketFormat::Protobuf
            } else {
                PacketFormat::Legacy
            };
            let raw = codec::encode_audio_packet(audio, *target, format);
            client.try_enqueue_voice_tcp(raw);
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
            tracing::warn!(session = u32::from(sender.get_session_id()), "voice routing task already spawned");
            return;
        }
    };
    let weak_sender = Arc::downgrade(&sender);
    tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            let Some(sender) = weak_sender.upgrade() else { break };
            route_voice(&server, &sender, &payload.decoded_audio, payload.is_udp).await;
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
            let Some(client) = weak_client.upgrade() else { break };
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
