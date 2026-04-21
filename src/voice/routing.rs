//! Voice routing logic — determines recipients and dispatches audio packets.

use std::sync::Arc;

use prost::Message as _;

use crate::{
    client::Client,
    mumble_udp::{Audio, audio},
    server::Server,
};

use super::udp_batch::{self, QueuedDatagram};

/// Route an incoming voice packet to its intended recipients.
///
/// `sender` is the client that originated the audio.
/// `audio` is the decoded `Audio` protobuf message.
/// `is_udp` indicates whether the packet arrived via UDP (true) or TCP tunnel (false).
pub async fn route_voice(
    server: &Arc<Box<Server>>,
    sender: &Arc<Box<Client>>,
    audio: &Audio,
    is_udp: bool,
) {
    let sender_id = sender.get_session_id();
    let sender_channel = sender.get_current_channel_id().await;

    // Check if sender is muted/suppressed
    {
        let gs = sender.read_global_state().await;
        if gs.is_muted() || gs.is_suppressed() || gs.is_self_muted() {
            return;
        }
    }

    // Determine target type from the header
    let target = audio.header.as_ref().map(|h| match h {
        audio::Header::Target(t) => *t,
        audio::Header::Context(_) => 0,
    }).unwrap_or(0);

    // Build the outgoing Audio message (server → client format)
    let outgoing = Audio {
        header: Some(audio::Header::Context(0)), // normal speech context
        sender_session: u32::from(sender_id),
        frame_number: audio.frame_number,
        opus_data: audio.opus_data.clone(),
        positional_data: audio.positional_data.clone(),
        volume_adjustment: 0.0,
        is_terminator: audio.is_terminator,
    };

    // Collect (client, audio) pairs for batched sending
    let mut targets: Vec<(Arc<Box<Client>>, Audio)> = Vec::new();

    let all_clients = server.get_clients().get_all_clients().await;

    if target == 0 {
        // ── Normal speech: send to all channel members ───────────────────
        for client in &all_clients {
            if client.get_session_id() == sender_id {
                continue;
            }
            if !client.is_authenticated().await {
                continue;
            }
            if client.get_current_channel_id().await != sender_channel {
                // Check if this client is listening to the sender's channel
                let gs = client.read_global_state().await;
                if !gs.is_listening_channel(sender_channel) {
                    continue;
                }
                // Listening context
                let mut listen_out = outgoing.clone();
                listen_out.header = Some(audio::Header::Context(3)); // channel listener
                targets.push((client.clone(), listen_out));
                continue;
            }
            targets.push((client.clone(), outgoing.clone()));
        }
    } else if target == 0x1F {
        // ── Server loopback (target = 31) ────────────────────────────────
        targets.push((sender.clone(), outgoing));
    } else {
        // ── Whisper/shout target ─────────────────────────────────────────
        let udp_state = sender.udp_state().await;
        let voice_target = udp_state.voice_target(target);

        if let Some(vt) = voice_target {
            // Direct session targets
            for session_raw in vt.sessions() {
                let session_id =
                    crate::client::client_session_identifier::ClientSessionIdentifier::from(*session_raw);
                if let Some(client) = server.get_clients().get_client(session_id).await {
                    if client.is_authenticated().await {
                        let mut whisper_out = outgoing.clone();
                        whisper_out.header = Some(audio::Header::Context(2)); // whisper
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
                    if !client.is_authenticated().await {
                        continue;
                    }
                    if channel_ids.contains(&client.get_current_channel_id().await) {
                        let mut shout_out = outgoing.clone();
                        shout_out.header = Some(audio::Header::Context(1)); // shout
                        targets.push((client.clone(), shout_out));
                    }
                }
            }
        }
    }

    // ── Flush all targets ────────────────────────────────────────────────
    flush_voice_batch(server, &targets, is_udp).await;
}

/// Encrypt and send voice packets to all targets.
///
/// On the UDP path, packets are encrypted and collected into a batched
/// send for a single syscall (Linux) or sent per-packet (other OS).
/// On the TCP path, each packet is tunnelled individually.
async fn flush_voice_batch(
    server: &Arc<Box<Server>>,
    targets: &[(Arc<Box<Client>>, Audio)],
    is_udp: bool,
) {
    if targets.is_empty() {
        return;
    }

    if is_udp {
        let socket = server.get_udp_socket();
        let mut batch: Vec<QueuedDatagram> = Vec::with_capacity(targets.len());

        for (client, audio) in targets {
            let udp_addr = match client.get_udp_address() {
                Some(a) => a,
                None => {
                    // No UDP address — fall back to TCP tunnel
                    let message = crate::messages::Message::UDPTunnel(
                        prost::Message::encode_to_vec(audio),
                    );
                    let _ = client.write_proto_message(&message).await;
                    continue;
                }
            };

            let mut crypt = client.crypt_state().await;
            if let Some(ref mut state) = *crypt {
                let proto_bytes = prost::Message::encode_to_vec(audio);
                let mut buf = vec![0u8; proto_bytes.len() + state.overhead()];
                if state.encrypt(&mut buf, &proto_bytes).is_ok() {
                    batch.push(QueuedDatagram {
                        addr: udp_addr,
                        data: buf,
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
            let message = crate::messages::Message::UDPTunnel(
                prost::Message::encode_to_vec(audio),
            );
            let _ = client.write_proto_message(&message).await;
        }
    }
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
