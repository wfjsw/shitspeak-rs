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

/// Route an incoming voice packet to its intended recipients.
///
/// `sender` is the client that originated the audio.
/// `audio` is the decoded audio data.
/// `is_udp` indicates whether the packet arrived via UDP (true) or TCP tunnel (false).
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

    // Build the outgoing audio data (server → client format)
    let outgoing = DecodedAudio {
        target: 0, // will be overridden per-recipient
        sender_session: u32::from(sender_id),
        frame_number: audio.frame_number,
        opus_data: audio.opus_data.clone(),
        positional_data: audio.positional_data.clone(),
        volume_adjustment: 0.0,
        is_terminator: audio.is_terminator,
        format: audio.format,
    };

    // Collect (client, audio) pairs for batched sending
    let mut targets: Vec<(Arc<Box<Client>>, DecodedAudio)> = Vec::new();

    // Pre-encoded payload for cross-node delivery (NORMAL channel speech
    // only). Built up front while `outgoing` is still owned. Receivers
    // decode and re-target per local recipient, so we encode with the
    // speaker's chosen format and `target = 0`.
    let mut s2s_payload: Option<bytes::Bytes> = None;

    let all_clients = server.get_clients().get_all_clients().await;

    if target == 0 {
        tracing::trace!(
            session = u32::from(sender_id),
            channel = sender_channel,
            "routing normal channel speech"
        );

        s2s_payload = Some(codec::encode_audio_packet(&outgoing, audio.format));
        // ── Normal speech: send to all channel members ───────────────────
        // TODO: optimize
        for client in &all_clients {
            if client.get_session_id() == sender_id {
                continue;
            }
            if !client.is_authenticated() {
                continue;
            }
            if client.get_current_channel_id() != sender_channel {
                // Check if this client is listening to the sender's channel
                let gs = client.read_global_state();
                if !gs.is_listening_channel(sender_channel) {
                    continue;
                }
                // Listening context
                let mut listen_out = outgoing.clone();
                listen_out.target = 3; // AudioContext::LISTEN
                targets.push((client.clone(), listen_out));
                continue;
            }
            targets.push((client.clone(), outgoing.clone()));
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
        targets.push((sender.clone(), outgoing));
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

            // Direct session targets
            for session_raw in vt.sessions() {
                let session_id =
                    crate::client::client_session_identifier::ClientSessionIdentifier::from(*session_raw);
                if let Some(client) = server.get_clients().get_client(session_id).await {
                    if client.is_authenticated() {
                        let mut whisper_out = outgoing.clone();
                        whisper_out.target = 2; // AudioContext::WHISPER
                        targets.push((client, whisper_out));
                    }
                }
            }

            // Channel targets
            for ch_target in vt.channels() {
                let channel_ids = if ch_target.sub_channels() {
                    collect_subtree_ids(server, ch_target.id()).await
                } else {
                    vec![ch_target.id()]
                };

                for client in &all_clients {
                    if client.get_session_id() == sender_id {
                        continue;
                    }
                    if !client.is_authenticated() {
                        continue;
                    }
                    if channel_ids.contains(&client.get_current_channel_id()) {
                        let mut shout_out = outgoing.clone();
                        shout_out.target = 1; // AudioContext::SHOUT
                        targets.push((client.clone(), shout_out));
                    }
                }
            }
        }
    }

    // ── Flush all targets locally ────────────────────────────────────────
    flush_voice_batch(server, &targets, is_udp).await;

    // ── Cross-node delivery (NORMAL channel speech only for now) ─────────
    // Whisper/shout cross-node delivery requires shipping the resolved
    // recipient set in the envelope; deferred to a later phase. Local
    // delivery for whisper above is unaffected.
    //
    // `send_for_channel` routes via the configured `delivery_strategy`:
    // broadcast (default) or targeted multicast using the recipient
    // index. Targeted falls back to broadcast when the index has no
    // entry for the channel (cold start, sparse cluster).
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

/// Encrypt and send voice packets to all targets.
///
/// On the UDP path, packets are encoded (legacy or protobuf based on client
/// version), encrypted, and collected into a batched send for a single
/// syscall (Linux) or sent per-packet (other OS).
/// On the TCP path, each packet is tunnelled individually.
async fn flush_voice_batch(
    server: &Arc<Box<Server>>,
    targets: &[(Arc<Box<Client>>, DecodedAudio)],
    is_udp: bool,
) {
    if targets.is_empty() {
        return;
    }

    if is_udp {
        let socket = server.get_udp_socket();
        let mut batch: Vec<QueuedDatagram> = Vec::with_capacity(targets.len());

        for (client, audio) in targets {
            let format = if client.read_global_state().uses_protobuf() {
                PacketFormat::Protobuf
            } else {
                PacketFormat::Legacy
            };

            if client.prefers_tcp_tunnel() {
                let raw = codec::encode_audio_packet(audio, format);
                let message = crate::messages::Message::UDPTunnel(raw);
                let _ = client.write_proto_message(&message).await;
                continue;
            }

            let udp_addr = match client.get_udp_address() {
                Some(a) => a,
                None => {
                    // No UDP address — fall back to TCP tunnel
                    let raw = codec::encode_audio_packet(audio, format);
                    let message = crate::messages::Message::UDPTunnel(raw);
                    let _ = client.write_proto_message(&message).await;
                    continue;
                }
            };

            let mut crypt = client.crypt_state();
            if let Some(ref mut state) = *crypt {
                let raw = codec::encode_audio_packet(audio, format);
                let mut buf = vec![0u8; raw.len() + state.overhead()];
                if state.encrypt(&mut buf, &raw).is_ok() {
                    batch.push(QueuedDatagram {
                        addr: udp_addr,
                        data: bytes::Bytes::from(buf),
                    });
                }
            }
        }

        if let Err(e) = udp_batch::flush_batch(socket.as_ref(), &batch).await {
            tracing::warn!("UDP batch send error: {e}");
        }
    } else {
        // TCP tunnel path — send each individually
        for (client, audio) in targets {
            let format = if client.read_global_state().uses_protobuf() {
                PacketFormat::Protobuf
            } else {
                PacketFormat::Legacy
            };
            let raw = codec::encode_audio_packet(audio, format);
            let message = crate::messages::Message::UDPTunnel(raw);
            let _ = client.write_proto_message(&message).await;
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
