use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::{Mutex, mpsc};
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::policy::bundle_policy::RTCBundlePolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_remote::TrackRemote;

use crate::protocol::{
    ClientCommand, IceConnectionState, ServerEvent, SpeakerAssigned, VoiceSegment, VoiceTarget,
    decode_client_command, encode_server_event,
};
use crate::session::client_is_current;
use crate::voice::{
    InboundVoiceMetadata, RtpFrameNumberMapper, SpeakerAssignment, SsrcAllocator, VoiceTargetKind,
};
use shitspeak_runtime::client::AsyncMessageHandlerExt;
use shitspeak_runtime::client::Client;
use shitspeak_runtime::client::client_session_identifier::ClientSessionIdentifier;
use shitspeak_runtime::messages::Message;
use shitspeak_runtime::messages::encoder::AudioTarget;
use shitspeak_runtime::server::Server;
use shitspeak_runtime::voice::codec::{Audio, AudioPayload, OpusPayload, PacketFormat};
use shitspeak_runtime_config::{WebRtcConfig, WebRtcIceServerConfig};

const CONTROL_LABEL: &str = "shitspeak-control";
const OPUS_FRAME_DURATION: Duration = Duration::from_millis(20);

pub struct WebRtcPeer {
    peer: Arc<RTCPeerConnection>,
    control: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    voice_metadata: Arc<Mutex<InboundVoiceMetadata>>,
}

#[derive(Debug)]
pub enum PeerSignal {
    ServerEvent(ServerEvent),
    Answer { sdp: String },
    IceCandidate { candidate: RTCIceCandidateInit },
}

#[derive(Debug, Clone)]
struct ActiveOutboundSpeaker {
    speaker_session: u32,
    slot: usize,
    epoch: u64,
    context: String,
    channel_id: u32,
    last_rtp_timestamp: u32,
}

struct OutboundSpeakerSlot {
    ssrc: u32,
    track_id: String,
    track: Arc<TrackLocalStaticSample>,
}

impl WebRtcPeer {
    pub async fn new(
        config: WebRtcConfig,
        server: Option<Arc<Box<Server>>>,
        client: Option<Arc<Box<Client>>>,
        signaling_tx: mpsc::Sender<PeerSignal>,
    ) -> io::Result<Self> {
        let peer = Arc::new(new_peer_connection(&config).await?);
        let control = Arc::new(Mutex::new(None));
        let voice_metadata = Arc::new(Mutex::new(InboundVoiceMetadata::new()));
        let frame_numbers = Arc::new(Mutex::new(RtpFrameNumberMapper::new()));

        register_ice_handlers(&peer, signaling_tx.clone());
        register_data_channel_handler(
            &peer,
            Arc::clone(&control),
            Arc::clone(&voice_metadata),
            server.clone(),
            client.clone(),
            signaling_tx.clone(),
        );
        register_track_handler(
            &peer,
            Arc::clone(&voice_metadata),
            Arc::clone(&frame_numbers),
            server.clone(),
            client.clone(),
        );

        if let Some(client) = client {
            spawn_web_voice_outbound_task(
                &peer,
                &config,
                server.clone(),
                client,
                signaling_tx.clone(),
            )
            .await?;
        }

        Ok(Self {
            peer,
            control,
            voice_metadata,
        })
    }

    pub async fn answer_offer(&self, sdp: String) -> io::Result<String> {
        let offer = RTCSessionDescription::offer(sdp).map_err(webrtc_error)?;
        self.peer
            .set_remote_description(offer)
            .await
            .map_err(webrtc_error)?;
        let answer = self.peer.create_answer(None).await.map_err(webrtc_error)?;
        let sdp = answer.sdp.clone();
        self.peer
            .set_local_description(answer)
            .await
            .map_err(webrtc_error)?;
        Ok(sdp)
    }

    pub async fn add_ice_candidate(&self, candidate: serde_json::Value) -> io::Result<()> {
        let candidate = serde_json::from_value::<RTCIceCandidateInit>(candidate)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.peer
            .add_ice_candidate(candidate)
            .await
            .map_err(webrtc_error)
    }

    pub async fn send_event(&self, event: &ServerEvent) -> bool {
        let Some(control) = self.control.lock().await.clone() else {
            return false;
        };
        if control.ready_state() != RTCDataChannelState::Open {
            return false;
        };
        let Ok(payload) = encode_server_event(event) else {
            return false;
        };
        match control.send_text(payload).await {
            Ok(_) => true,
            Err(error) => {
                tracing::trace!(error = %error, "failed to send web event over data channel");
                false
            }
        }
    }

    pub async fn close(&self) {
        let _ = self.peer.close().await;
    }

    pub async fn apply_voice_control(
        &self,
        ptt: bool,
        target: VoiceTarget,
        epoch: u64,
    ) -> ServerEvent {
        apply_voice_control_metadata(&self.voice_metadata, ptt, target, epoch).await
    }
}

async fn new_peer_connection(config: &WebRtcConfig) -> io::Result<RTCPeerConnection> {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .map_err(webrtc_error)?;
    let registry =
        register_default_interceptors(Registry::new(), &mut media_engine).map_err(webrtc_error)?;
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();
    api.new_peer_connection(RTCConfiguration {
        ice_servers: config.ice_servers.iter().map(ice_server).collect(),
        bundle_policy: RTCBundlePolicy::MaxBundle,
        ..Default::default()
    })
    .await
    .map_err(webrtc_error)
}

fn ice_server(server: &WebRtcIceServerConfig) -> RTCIceServer {
    RTCIceServer {
        urls: server.urls.clone(),
        username: server.username.clone().unwrap_or_default(),
        credential: server.credential.clone().unwrap_or_default(),
    }
}

fn register_ice_handlers(peer: &Arc<RTCPeerConnection>, signaling_tx: mpsc::Sender<PeerSignal>) {
    let tx = signaling_tx.clone();
    peer.on_ice_candidate(Box::new(move |candidate| {
        let tx = tx.clone();
        Box::pin(async move {
            let Some(candidate) = candidate else {
                return;
            };
            match candidate.to_json() {
                Ok(candidate) => {
                    let _ = tx.send(PeerSignal::IceCandidate { candidate }).await;
                }
                Err(error) => {
                    tracing::trace!(error = %error, "failed to serialize web ICE candidate");
                }
            }
        })
    }));

    peer.on_ice_connection_state_change(Box::new(move |state| {
        let tx = signaling_tx.clone();
        Box::pin(async move {
            let _ = tx
                .send(PeerSignal::ServerEvent(ServerEvent::IceConnectionState {
                    state: ice_connection_state(state),
                }))
                .await;
        })
    }));
}

fn register_data_channel_handler(
    peer: &Arc<RTCPeerConnection>,
    control: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    voice_metadata: Arc<Mutex<InboundVoiceMetadata>>,
    server: Option<Arc<Box<Server>>>,
    client: Option<Arc<Box<Client>>>,
    signaling_tx: mpsc::Sender<PeerSignal>,
) {
    peer.on_data_channel(Box::new(move |channel| {
        let control = Arc::clone(&control);
        let voice_metadata = Arc::clone(&voice_metadata);
        let server = server.clone();
        let client = client.clone();
        let signaling_tx = signaling_tx.clone();
        Box::pin(async move {
            if channel.label() != CONTROL_LABEL {
                return;
            }
            *control.lock().await = Some(Arc::clone(&channel));
            channel.on_message(Box::new(move |message| {
                let voice_metadata = Arc::clone(&voice_metadata);
                let server = server.clone();
                let client = client.clone();
                let signaling_tx = signaling_tx.clone();
                Box::pin(async move {
                    handle_control_message(message, voice_metadata, server, client, signaling_tx)
                        .await;
                })
            }));
        })
    }));
}

async fn handle_control_message(
    message: DataChannelMessage,
    voice_metadata: Arc<Mutex<InboundVoiceMetadata>>,
    server: Option<Arc<Box<Server>>>,
    client: Option<Arc<Box<Client>>>,
    signaling_tx: mpsc::Sender<PeerSignal>,
) {
    if !message.is_string {
        let _ = signaling_tx
            .send(PeerSignal::ServerEvent(ServerEvent::Error {
                message: "binary control messages are not supported".to_string(),
            }))
            .await;
        return;
    }

    let Ok(text) = std::str::from_utf8(&message.data) else {
        let _ = signaling_tx
            .send(PeerSignal::ServerEvent(ServerEvent::Error {
                message: "invalid utf-8 control message".to_string(),
            }))
            .await;
        return;
    };
    let Ok(command) = decode_client_command(text) else {
        let _ = signaling_tx
            .send(PeerSignal::ServerEvent(ServerEvent::Error {
                message: "invalid control message".to_string(),
            }))
            .await;
        return;
    };

    if let ClientCommand::VoiceControl { ptt, target, epoch } = command {
        let event = apply_voice_control_metadata(&voice_metadata, ptt, target, epoch).await;
        let _ = signaling_tx.send(PeerSignal::ServerEvent(event)).await;
        return;
    }

    let (Some(server), Some(client)) = (server, client) else {
        let _ = signaling_tx
            .send(PeerSignal::ServerEvent(ServerEvent::Error {
                message: "web control command is not wired to this server".to_string(),
            }))
            .await;
        return;
    };
    let Some(message) = control_message_from_command(&client, command) else {
        return;
    };
    if let Err(error) = client.handle_message(&server, message).await {
        let _ = signaling_tx
            .send(PeerSignal::ServerEvent(ServerEvent::Error {
                message: format!("control command failed: {error}"),
            }))
            .await;
    }
}

async fn apply_voice_control_metadata(
    voice_metadata: &Arc<Mutex<InboundVoiceMetadata>>,
    ptt: bool,
    target: VoiceTarget,
    epoch: u64,
) -> ServerEvent {
    let target = voice_target_kind(target);
    let mut metadata = voice_metadata.lock().await;
    metadata.update_epoch(epoch, target, ptt);
    metadata.acknowledge(epoch);
    ServerEvent::VoiceControlAck { epoch }
}

fn register_track_handler(
    peer: &Arc<RTCPeerConnection>,
    voice_metadata: Arc<Mutex<InboundVoiceMetadata>>,
    frame_numbers: Arc<Mutex<RtpFrameNumberMapper>>,
    server: Option<Arc<Box<Server>>>,
    client: Option<Arc<Box<Client>>>,
) {
    peer.on_track(Box::new(move |track, _receiver, _transceiver| {
        let voice_metadata = Arc::clone(&voice_metadata);
        let frame_numbers = Arc::clone(&frame_numbers);
        let server = server.clone();
        let client = client.clone();
        Box::pin(async move {
            spawn_inbound_audio_task(track, voice_metadata, frame_numbers, server, client);
        })
    }));
}

fn spawn_inbound_audio_task(
    track: Arc<TrackRemote>,
    voice_metadata: Arc<Mutex<InboundVoiceMetadata>>,
    frame_numbers: Arc<Mutex<RtpFrameNumberMapper>>,
    server: Option<Arc<Box<Server>>>,
    client: Option<Arc<Box<Client>>>,
) {
    let (Some(server), Some(client)) = (server, client) else {
        return;
    };
    tokio::spawn(async move {
        loop {
            let packet = tokio::select! {
                biased;
                _ = client.disconnected() => break,
                packet = track.read_rtp() => match packet {
                    Ok((packet, _)) => packet,
                    Err(_) => break,
                },
            };
            let Some(epoch) = voice_metadata.lock().await.routable_epoch() else {
                continue;
            };
            if !epoch.ptt {
                continue;
            }
            let frame_number = frame_numbers
                .lock()
                .await
                .map_packet(packet.header.ssrc, epoch.epoch, packet.header.timestamp)
                .frame_number;
            let audio = Audio {
                target: audio_target(epoch.target),
                sender_session: Some(client.get_session_id()),
                frame_number,
                audio_payload: AudioPayload::Opus(OpusPayload {
                    frame: packet.payload,
                    is_terminator: false,
                }),
                positional_data: None,
                volume_adjustment: 1.0,
                format: PacketFormat::Protobuf,
            };
            if !client_is_current(&server, &client).await {
                break;
            }
            client.push_voice_routing(audio);
        }
    });
}

async fn spawn_web_voice_outbound_task(
    peer: &Arc<RTCPeerConnection>,
    config: &WebRtcConfig,
    server: Option<Arc<Box<Server>>>,
    client: Arc<Box<Client>>,
    signaling_tx: mpsc::Sender<PeerSignal>,
) -> io::Result<()> {
    let speaker_slots = create_outbound_speaker_slots(peer, config.max_speaker_ssrcs).await?;
    let speaker_pool: Vec<u32> = speaker_slots.iter().map(|slot| slot.ssrc).collect();
    let slot_by_ssrc: HashMap<u32, usize> = speaker_slots
        .iter()
        .enumerate()
        .map(|(index, slot)| (slot.ssrc, index))
        .collect();

    let session_id = u32::from(client.get_session_id());
    let mut rx = match client.take_voice_tcp_rx() {
        Some(rx) => rx,
        None => return Ok(()),
    };
    tokio::spawn(async move {
        let mut speakers = SsrcAllocator::from_ssrcs(speaker_pool);
        let mut active: HashMap<u32, ActiveOutboundSpeaker> = HashMap::new();
        let mut next_epoch = 1u64;
        while let Some(raw) = rx.recv().await {
            let Ok(audio) = Audio::decode(&raw, None) else {
                continue;
            };
            let AudioPayload::Opus(opus) = &audio.audio_payload else {
                continue;
            };
            let Some(sender_session_id) = audio.sender_session.map(u32::from) else {
                continue;
            };
            if sender_session_id == session_id {
                continue;
            }

            let rtp_timestamp = audio.frame_number as u32;
            if !active.contains_key(&sender_session_id) {
                let epoch = next_epoch;
                next_epoch = next_epoch.saturating_add(1);
                let Ok(assignment) = speakers.assign(sender_session_id, epoch) else {
                    tracing::trace!(
                        speaker_session = sender_session_id,
                        "web speaker SSRC pool exhausted, dropping routed frame"
                    );
                    continue;
                };
                let Some(slot) = slot_by_ssrc.get(&assignment.ssrc).copied() else {
                    tracing::trace!(
                        ssrc = assignment.ssrc,
                        "web speaker assignment has no negotiated track slot"
                    );
                    speakers.release(sender_session_id);
                    continue;
                };
                let context = outbound_context(&audio);
                let channel_id = outbound_speaker_channel(&server, sender_session_id)
                    .await
                    .unwrap_or_else(|| client.get_current_channel_id());

                let (assigned, segment) = speaker_assignment_events(
                    &audio,
                    &assignment,
                    speaker_slots[slot].track_id.clone(),
                    channel_id,
                );
                send_peer_event(&signaling_tx, ServerEvent::SpeakerAssigned(assigned)).await;
                send_peer_event(&signaling_tx, ServerEvent::VoiceSegmentStart(segment)).await;

                active.insert(
                    sender_session_id,
                    ActiveOutboundSpeaker {
                        speaker_session: assignment.speaker_session,
                        slot,
                        epoch: assignment.epoch,
                        context,
                        channel_id,
                        last_rtp_timestamp: rtp_timestamp,
                    },
                );
            }

            if let Some(current) = active.get_mut(&sender_session_id) {
                current.last_rtp_timestamp = rtp_timestamp;
            }

            if !opus.frame.is_empty() {
                let Some(current) = active.get(&sender_session_id) else {
                    continue;
                };
                let _ = speaker_slots[current.slot]
                    .track
                    .write_sample(&Sample {
                        data: opus.frame.clone(),
                        timestamp: SystemTime::now(),
                        duration: OPUS_FRAME_DURATION,
                        packet_timestamp: rtp_timestamp,
                        prev_dropped_packets: 0,
                        prev_padding_packets: 0,
                    })
                    .await;
            }

            if opus.is_terminator {
                if let Some(current) = active.remove(&sender_session_id) {
                    let ssrc = speaker_slots[current.slot].ssrc;
                    send_peer_event(
                        &signaling_tx,
                        ServerEvent::VoiceSegmentEnd(VoiceSegment {
                            ssrc,
                            speaker_session: current.speaker_session,
                            context: current.context,
                            channel_id: current.channel_id,
                            rtp_timestamp,
                            epoch: current.epoch,
                        }),
                    )
                    .await;
                    speakers.release(current.speaker_session);
                }
            }
        }
    });

    Ok(())
}

async fn create_outbound_speaker_slots(
    peer: &Arc<RTCPeerConnection>,
    capacity: u32,
) -> io::Result<Vec<OutboundSpeakerSlot>> {
    let capacity = capacity.max(1);
    let mut slots = Vec::with_capacity(capacity as usize);
    for index in 0..capacity {
        let track_id = format!("speaker-slot-{index}");
        let track = Arc::new(TrackLocalStaticSample::new(
            opus_codec_capability(),
            track_id.clone(),
            "shitspeak".to_string(),
        ));
        let outbound_track: Arc<dyn TrackLocal + Send + Sync> = track.clone();
        let transceiver = peer
            .add_transceiver_from_track(
                outbound_track,
                Some(RTCRtpTransceiverInit {
                    direction: RTCRtpTransceiverDirection::Sendonly,
                    send_encodings: Vec::new(),
                }),
            )
            .await
            .map_err(webrtc_error)?;
        let sender = transceiver.sender().await;
        let ssrc = sender
            .get_parameters()
            .await
            .encodings
            .first()
            .map(|encoding| encoding.ssrc)
            .filter(|ssrc| *ssrc != 0)
            .unwrap_or_else(rand::random::<u32>);
        slots.push(OutboundSpeakerSlot {
            ssrc,
            track_id,
            track,
        });
    }
    Ok(slots)
}

fn opus_codec_capability() -> RTCRtpCodecCapability {
    RTCRtpCodecCapability {
        mime_type: MIME_TYPE_OPUS.to_string(),
        clock_rate: 48_000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_string(),
        rtcp_feedback: Vec::new(),
    }
}

async fn send_peer_event(signaling_tx: &mpsc::Sender<PeerSignal>, event: ServerEvent) {
    let _ = signaling_tx.send(PeerSignal::ServerEvent(event)).await;
}

async fn outbound_speaker_channel(
    server: &Option<Arc<Box<Server>>>,
    speaker_session: u32,
) -> Option<u32> {
    let server = server.as_ref()?;
    let client = server
        .get_clients()
        .get_client(ClientSessionIdentifier::from(speaker_session))
        .await?;
    Some(client.get_current_channel_id())
}

fn outbound_context(audio: &Audio) -> String {
    match audio.target {
        AudioTarget::Normal => "normal".to_string(),
        AudioTarget::ServerLoopback => "loopback".to_string(),
        AudioTarget::VoiceTarget(slot) => format!("target:{slot}"),
    }
}

fn speaker_assignment_events(
    audio: &Audio,
    assignment: &SpeakerAssignment,
    track_id: String,
    channel_id: u32,
) -> (SpeakerAssigned, VoiceSegment) {
    let rtp_timestamp = audio.frame_number as u32;
    (
        SpeakerAssigned {
            ssrc: assignment.ssrc,
            speaker_session: assignment.speaker_session,
            track_id,
            epoch: assignment.epoch,
        },
        VoiceSegment {
            ssrc: assignment.ssrc,
            speaker_session: assignment.speaker_session,
            context: outbound_context(audio),
            channel_id,
            rtp_timestamp,
            epoch: assignment.epoch,
        },
    )
}

fn control_message_from_command(
    client: &Arc<Box<Client>>,
    command: ClientCommand,
) -> Option<Message> {
    match command {
        ClientCommand::Authenticate { .. } => None,
        ClientCommand::JoinChannel { channel_id } => Some(
            shitspeak_runtime::messages::encoder::UserState {
                session: Some(client.get_session_id()),
                channel_id: Some(channel_id),
                ..Default::default()
            }
            .into(),
        ),
        ClientCommand::SendText { text } => Some(
            shitspeak_runtime::messages::encoder::TextMessage {
                actor: None,
                session: Vec::new(),
                channel_id: vec![client.get_current_channel_id()],
                tree_id: Vec::new(),
                message: text,
            }
            .into(),
        ),
        ClientCommand::SetMute { muted } => Some(
            shitspeak_runtime::messages::encoder::UserState {
                session: Some(client.get_session_id()),
                self_mute: Some(muted),
                ..Default::default()
            }
            .into(),
        ),
        ClientCommand::SetDeaf { deafened } => Some(
            shitspeak_runtime::messages::encoder::UserState {
                session: Some(client.get_session_id()),
                self_deaf: Some(deafened),
                ..Default::default()
            }
            .into(),
        ),
        ClientCommand::VoiceControl { .. } => None,
    }
}

fn voice_target_kind(target: VoiceTarget) -> VoiceTargetKind {
    match target {
        VoiceTarget::Normal => VoiceTargetKind::Normal,
        VoiceTarget::ServerLoopback => VoiceTargetKind::ServerLoopback,
        VoiceTarget::Slot(slot) => VoiceTargetKind::Slot(slot),
    }
}

fn audio_target(target: VoiceTargetKind) -> AudioTarget {
    match target {
        VoiceTargetKind::Normal => AudioTarget::Normal,
        VoiceTargetKind::ServerLoopback => AudioTarget::ServerLoopback,
        VoiceTargetKind::Slot(slot) => AudioTarget::VoiceTarget(slot),
    }
}

fn ice_connection_state(state: RTCIceConnectionState) -> IceConnectionState {
    match state {
        RTCIceConnectionState::Checking => IceConnectionState::Checking,
        RTCIceConnectionState::Connected => IceConnectionState::Connected,
        RTCIceConnectionState::Completed => IceConnectionState::Completed,
        RTCIceConnectionState::Disconnected => IceConnectionState::Disconnected,
        RTCIceConnectionState::Failed => IceConnectionState::Failed,
        RTCIceConnectionState::Closed => IceConnectionState::Closed,
        RTCIceConnectionState::New | RTCIceConnectionState::Unspecified => IceConnectionState::New,
    }
}

fn webrtc_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use shitspeak_runtime_config::WebRtcIceServerConfig;
    use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;

    fn install_crypto_provider() {
        static CRYPTO_PROVIDER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        CRYPTO_PROVIDER.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[test]
    fn maps_configured_ice_server() {
        let server = ice_server(&WebRtcIceServerConfig {
            urls: vec!["turn:turn.example.test:3478".to_string()],
            username: Some("user".to_string()),
            credential: Some("pass".to_string()),
        });

        assert_eq!(server.urls, vec!["turn:turn.example.test:3478"]);
        assert_eq!(server.username, "user");
        assert_eq!(server.credential, "pass");
    }

    #[test]
    fn maps_voice_targets() {
        assert_eq!(audio_target(VoiceTargetKind::Normal), AudioTarget::Normal);
        assert_eq!(
            audio_target(VoiceTargetKind::ServerLoopback),
            AudioTarget::ServerLoopback
        );
        assert_eq!(
            audio_target(VoiceTargetKind::Slot(7)),
            AudioTarget::VoiceTarget(7)
        );
    }

    #[tokio::test]
    async fn answer_offer_negotiates_bounded_sendonly_speaker_slots() {
        let mut offer_media_engine = MediaEngine::default();
        offer_media_engine.register_default_codecs().unwrap();
        let offer_api = APIBuilder::new()
            .with_media_engine(offer_media_engine)
            .build();
        let offer_peer = offer_api
            .new_peer_connection(RTCConfiguration {
                bundle_policy: RTCBundlePolicy::MaxBundle,
                ..Default::default()
            })
            .await
            .unwrap();
        offer_peer
            .create_data_channel(CONTROL_LABEL, None)
            .await
            .unwrap();
        for _ in 0..3 {
            offer_peer
                .add_transceiver_from_kind(
                    RTPCodecType::Audio,
                    Some(RTCRtpTransceiverInit {
                        direction: RTCRtpTransceiverDirection::Recvonly,
                        send_encodings: Vec::new(),
                    }),
                )
                .await
                .unwrap();
        }

        let offer = offer_peer.create_offer(None).await.unwrap();
        offer_peer
            .set_local_description(offer.clone())
            .await
            .unwrap();

        let (signal_tx, _signal_rx) = mpsc::channel(16);
        let peer = WebRtcPeer::new(
            WebRtcConfig {
                max_speaker_ssrcs: 3,
                ..Default::default()
            },
            None,
            None,
            signal_tx,
        )
        .await
        .unwrap();

        let answer_sdp = peer.answer_offer(offer.sdp).await.unwrap();
        assert!(answer_sdp.starts_with("v=0"));
        offer_peer
            .set_remote_description(RTCSessionDescription::answer(answer_sdp).unwrap())
            .await
            .unwrap();

        let server_transceivers = peer.peer.get_transceivers().await;
        let server_audio = server_transceivers
            .iter()
            .filter(|transceiver| transceiver.kind() == RTPCodecType::Audio)
            .collect::<Vec<_>>();
        assert_eq!(server_audio.len(), 3);
        assert!(server_audio.iter().all(|transceiver| {
            transceiver.direction() == RTCRtpTransceiverDirection::Sendonly
                && transceiver.current_direction() == RTCRtpTransceiverDirection::Sendonly
        }));

        let offer_transceivers = offer_peer.get_transceivers().await;
        let offer_audio = offer_transceivers
            .iter()
            .filter(|transceiver| transceiver.kind() == RTPCodecType::Audio)
            .collect::<Vec<_>>();
        assert_eq!(offer_audio.len(), 3);
        assert!(offer_audio.iter().all(|transceiver| {
            transceiver.direction() == RTCRtpTransceiverDirection::Recvonly
                && transceiver.current_direction() == RTCRtpTransceiverDirection::Recvonly
        }));

        peer.close().await;
        offer_peer.close().await.unwrap();
    }

    #[tokio::test]
    async fn send_event_delivers_over_open_control_channel() {
        install_crypto_provider();

        let mut offer_media_engine = MediaEngine::default();
        offer_media_engine.register_default_codecs().unwrap();
        let offer_api = APIBuilder::new()
            .with_media_engine(offer_media_engine)
            .build();
        let offer_peer = Arc::new(
            offer_api
                .new_peer_connection(RTCConfiguration {
                    bundle_policy: RTCBundlePolicy::MaxBundle,
                    ..Default::default()
                })
                .await
                .unwrap(),
        );
        let control = offer_peer
            .create_data_channel(CONTROL_LABEL, None)
            .await
            .unwrap();

        let (open_tx, mut open_rx) = mpsc::channel(1);
        control.on_open(Box::new(move || {
            let open_tx = open_tx.clone();
            Box::pin(async move {
                let _ = open_tx.send(()).await;
            })
        }));

        let (received_tx, mut received_rx) = mpsc::channel(1);
        control.on_message(Box::new(move |message| {
            let received_tx = received_tx.clone();
            Box::pin(async move {
                if !message.is_string {
                    return;
                }
                let Ok(text) = std::str::from_utf8(&message.data) else {
                    return;
                };
                let Ok(event) = serde_json::from_str::<ServerEvent>(text) else {
                    return;
                };
                let _ = received_tx.send(event).await;
            })
        }));

        let offer = offer_peer.create_offer(None).await.unwrap();
        let mut offer_gathering_complete = offer_peer.gathering_complete_promise().await;
        offer_peer.set_local_description(offer).await.unwrap();
        let _ = offer_gathering_complete.recv().await;
        let offer = offer_peer.local_description().await.unwrap();

        let (signal_tx, mut signal_rx) = mpsc::channel(16);
        let peer = WebRtcPeer::new(WebRtcConfig::default(), None, None, signal_tx)
            .await
            .unwrap();

        let answer_sdp = peer.answer_offer(offer.sdp).await.unwrap();
        offer_peer
            .set_remote_description(RTCSessionDescription::answer(answer_sdp).unwrap())
            .await
            .unwrap();

        let offer_peer_for_candidates = Arc::clone(&offer_peer);
        let candidate_task = tokio::spawn(async move {
            while let Some(signal) = signal_rx.recv().await {
                if let PeerSignal::IceCandidate { candidate } = signal {
                    let _ = offer_peer_for_candidates.add_ice_candidate(candidate).await;
                }
            }
        });

        tokio::time::timeout(Duration::from_secs(5), open_rx.recv())
            .await
            .expect("control channel should open")
            .expect("control channel open signal should be sent");

        let event = ServerEvent::VoiceControlAck { epoch: 11 };
        let delivered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if peer.send_event(&event).await {
                    break true;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("server control channel should accept event");
        assert!(delivered);

        let received = tokio::time::timeout(Duration::from_secs(5), received_rx.recv())
            .await
            .expect("event should arrive over control channel")
            .expect("event channel should remain open");
        assert_eq!(received, event);

        candidate_task.abort();
        peer.close().await;
        offer_peer.close().await.unwrap();
    }

    #[tokio::test]
    async fn send_event_reports_fallback_before_control_channel_opens() {
        let (signal_tx, _signal_rx) = mpsc::channel(16);
        let peer = WebRtcPeer::new(WebRtcConfig::default(), None, None, signal_tx)
            .await
            .unwrap();

        assert!(
            !peer
                .send_event(&ServerEvent::VoiceControlAck { epoch: 7 })
                .await
        );

        peer.close().await;
    }

    #[test]
    fn speaker_assignment_events_include_track_context_and_timestamps() {
        let audio = Audio {
            target: AudioTarget::VoiceTarget(4),
            sender_session: Some(ClientSessionIdentifier::from(42)),
            frame_number: 90_001,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(&[0x01, 0x02]),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Protobuf,
        };
        let assignment = SpeakerAssignment {
            ssrc: 77,
            speaker_session: 42,
            epoch: 9,
        };

        let (assigned, segment) =
            speaker_assignment_events(&audio, &assignment, "speaker-slot-2".to_string(), 5);

        assert_eq!(
            assigned,
            SpeakerAssigned {
                ssrc: 77,
                speaker_session: 42,
                track_id: "speaker-slot-2".to_string(),
                epoch: 9,
            }
        );
        assert_eq!(
            segment,
            VoiceSegment {
                ssrc: 77,
                speaker_session: 42,
                context: "target:4".to_string(),
                channel_id: 5,
                rtp_timestamp: 90_001,
                epoch: 9,
            }
        );
    }
}
