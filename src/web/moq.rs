use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;

use crate::api::Authenticator;
use crate::channel_handler::SessionChannelShadow;
use crate::client::state_log::ClientStateOperation;
use crate::client::visibility::UserVisibilityState;
use crate::client::{client_session_identifier::ClientSessionIdentifier, Client};
use crate::config::{WebConfig, WebMoqConfig};
use crate::messages::Message;
use crate::server::Server;
use crate::voice::codec::{Audio, AudioPayload, OpusPayload, PacketFormat};
use crate::web::protocol::{
    decode_client_command, encode_server_event, ClientCommand, ServerEvent, SpeakerAssigned,
    VoiceSegment, VoiceTarget,
};
use crate::web::session::{
    apply_control_command, initial_server_events, server_event_from_message, WebSessionContext,
    WebSessionTransport,
};
use crate::web::voice::{InboundVoiceMetadata, SsrcAllocator, VoiceTargetKind};

pub const PATH: &str = "/web/moq";
pub const BROADCAST_PATH: &str = "web/moq";
pub const CATALOG_TRACK: &str = "catalog.json";
pub const CONTROL_UP_TRACK: &str = "control/up";
pub const CONTROL_DOWN_TRACK: &str = "control/down";
pub const AUDIO_UP_MIC_TRACK: &str = "audio/up/mic";
pub const AUDIO_DOWN_SLOT_PREFIX: &str = "audio/down/slot/";

const MOQ_AUDIO_MAGIC: &[u8; 4] = b"SSMA";
const MOQ_AUDIO_VERSION: u8 = 1;
const MOQ_AUDIO_FLAG_TERMINATOR: u8 = 0x01;
const MOQ_FIRST_DOWN_SLOT_SSRC: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoqTrackNames {
    control_up: String,
    control_down: String,
    audio_up_mic: String,
    catalog: String,
}

impl Default for MoqTrackNames {
    fn default() -> Self {
        Self {
            control_up: CONTROL_UP_TRACK.to_string(),
            control_down: CONTROL_DOWN_TRACK.to_string(),
            audio_up_mic: AUDIO_UP_MIC_TRACK.to_string(),
            catalog: CATALOG_TRACK.to_string(),
        }
    }
}

impl MoqTrackNames {
    pub fn control_up(&self) -> &str {
        &self.control_up
    }

    pub fn control_down(&self) -> &str {
        &self.control_down
    }

    pub fn audio_up_mic(&self) -> &str {
        &self.audio_up_mic
    }

    pub fn catalog(&self) -> &str {
        &self.catalog
    }

    pub fn audio_down_slot(slot: u32) -> String {
        format!("{AUDIO_DOWN_SLOT_PREFIX}{slot}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoqAudioFrame {
    timestamp_micros: u64,
    payload: Bytes,
    terminator: bool,
}

impl MoqAudioFrame {
    pub fn new(timestamp_micros: u64, payload: impl Into<Bytes>) -> Self {
        Self {
            timestamp_micros,
            payload: payload.into(),
            terminator: false,
        }
    }

    pub fn terminator(timestamp_micros: u64) -> Self {
        Self {
            timestamp_micros,
            payload: Bytes::new(),
            terminator: true,
        }
    }

    pub fn timestamp_micros(&self) -> u64 {
        self.timestamp_micros
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    pub fn is_terminator(&self) -> bool {
        self.terminator
    }

    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(14 + self.payload.len());
        out.extend_from_slice(MOQ_AUDIO_MAGIC);
        out.put_u8(MOQ_AUDIO_VERSION);
        out.put_u8(if self.terminator {
            MOQ_AUDIO_FLAG_TERMINATOR
        } else {
            0
        });
        out.put_u64(self.timestamp_micros);
        out.extend_from_slice(&self.payload);
        out.freeze()
    }

    pub fn decode(mut input: Bytes) -> Result<Self, MoqAudioFrameError> {
        if input.remaining() < 14 {
            return Err(MoqAudioFrameError::TooShort);
        }
        if &input[..4] != MOQ_AUDIO_MAGIC {
            return Err(MoqAudioFrameError::BadMagic);
        }
        input.advance(4);
        let version = input.get_u8();
        if version != MOQ_AUDIO_VERSION {
            return Err(MoqAudioFrameError::UnsupportedVersion(version));
        }
        let flags = input.get_u8();
        let timestamp_micros = input.get_u64();
        let terminator = flags & MOQ_AUDIO_FLAG_TERMINATOR != 0;
        Ok(Self {
            timestamp_micros,
            payload: input.copy_to_bytes(input.remaining()),
            terminator,
        })
    }

    pub fn from_audio(audio: &Audio) -> Option<Self> {
        let AudioPayload::Opus(opus) = &audio.audio_payload else {
            return None;
        };
        Some(Self {
            timestamp_micros: audio.frame_number,
            payload: opus.frame.clone(),
            terminator: opus.is_terminator,
        })
    }

    pub fn into_audio(
        self,
        sender_session: ClientSessionIdentifier,
        target: VoiceTargetKind,
    ) -> Audio {
        Audio {
            target: audio_target(target),
            sender_session: Some(sender_session),
            frame_number: self.timestamp_micros,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: self.payload,
                is_terminator: self.terminator,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Protobuf,
        }
    }

    #[cfg(feature = "moq")]
    pub fn to_hang_frame(&self) -> hang::container::Frame {
        hang::container::Frame {
            timestamp: hang::container::Timestamp::from_micros(self.timestamp_micros)
                .expect("timestamp should fit in MoQ varint"),
            payload: self.payload.clone(),
        }
    }

    #[cfg(feature = "moq")]
    pub fn from_hang_frame(frame: hang::container::Frame, terminator: bool) -> Self {
        Self {
            timestamp_micros: frame.timestamp.as_micros() as u64,
            payload: frame.payload,
            terminator,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoqAudioFrameError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u8),
}

impl std::fmt::Display for MoqAudioFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "MoQ audio frame is too short"),
            Self::BadMagic => write!(f, "MoQ audio frame has an invalid magic header"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported MoQ audio frame version {version}")
            }
        }
    }
}

impl std::error::Error for MoqAudioFrameError {}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MoqCatalog {
    tracks: Vec<MoqCatalogTrack>,
}

impl MoqCatalog {
    pub fn new(config: &WebMoqConfig) -> Self {
        let max_tracks = config.max_speaker_tracks.max(1);
        let mut tracks = Vec::with_capacity(max_tracks as usize + 4);
        tracks.push(MoqCatalogTrack::control(
            CONTROL_UP_TRACK,
            "client commands",
        ));
        tracks.push(MoqCatalogTrack::control(
            CONTROL_DOWN_TRACK,
            "server events",
        ));
        tracks.push(MoqCatalogTrack::audio(
            AUDIO_UP_MIC_TRACK,
            config.audio_bitrate,
        ));
        for slot in 0..max_tracks {
            tracks.push(MoqCatalogTrack::audio(
                MoqTrackNames::audio_down_slot(slot),
                config.audio_bitrate,
            ));
        }
        Self { tracks }
    }

    pub fn tracks(&self) -> &[MoqCatalogTrack] {
        &self.tracks
    }

    pub fn to_json_bytes(&self) -> Result<Bytes, serde_json::Error> {
        serde_json::to_vec(self).map(Bytes::from)
    }

    #[cfg(feature = "moq")]
    pub fn to_hang_catalog(&self, config: &WebMoqConfig) -> hang::Catalog {
        use std::collections::BTreeMap;

        let mut renditions = BTreeMap::new();
        for track in self
            .tracks
            .iter()
            .filter(|track| track.kind == MoqTrackKind::Audio)
        {
            renditions.insert(
                track.name.clone(),
                hang::catalog::AudioConfig {
                    codec: hang::catalog::AudioCodec::Opus,
                    sample_rate: 48_000,
                    channel_count: 1,
                    bitrate: Some(config.audio_bitrate as u64),
                    description: None,
                    container: hang::catalog::Container::Legacy,
                    jitter: None,
                },
            );
        }

        hang::Catalog {
            audio: hang::catalog::Audio { renditions },
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MoqCatalogTrack {
    name: String,
    kind: MoqTrackKind,
    codec: Option<&'static str>,
    sample_rate: Option<u32>,
    channels: Option<u32>,
    bitrate: Option<u32>,
    description: Option<&'static str>,
}

impl MoqCatalogTrack {
    fn audio(name: impl Into<String>, bitrate: u32) -> Self {
        Self {
            name: name.into(),
            kind: MoqTrackKind::Audio,
            codec: Some("opus"),
            sample_rate: Some(48_000),
            channels: Some(1),
            bitrate: Some(bitrate),
            description: None,
        }
    }

    fn control(name: impl Into<String>, description: &'static str) -> Self {
        Self {
            name: name.into(),
            kind: MoqTrackKind::Control,
            codec: None,
            sample_rate: None,
            channels: None,
            bitrate: None,
            description: Some(description),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> MoqTrackKind {
        self.kind
    }

    pub fn codec(&self) -> Option<&'static str> {
        self.codec
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MoqTrackKind {
    Audio,
    Control,
}

#[derive(Clone)]
pub struct MoqServer {
    config: WebConfig,
    fallback_cert_path: Option<PathBuf>,
    fallback_key_path: Option<PathBuf>,
    authenticator: Option<Arc<dyn Authenticator>>,
    server: Option<Arc<Box<Server>>>,
    provisional_server_id: Option<String>,
}

impl MoqServer {
    pub fn new(config: WebConfig) -> Self {
        Self {
            config,
            fallback_cert_path: None,
            fallback_key_path: None,
            authenticator: None,
            server: None,
            provisional_server_id: None,
        }
    }

    pub fn with_authenticator(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    pub fn with_server(mut self, server: Arc<Box<Server>>) -> Self {
        self.server = Some(server);
        self
    }

    pub fn with_provisional_server_id(mut self, server_id: Option<String>) -> Self {
        self.provisional_server_id = server_id;
        self
    }

    pub fn with_tls_fallback(
        mut self,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
    ) -> Self {
        self.fallback_cert_path = Some(cert_path.into());
        self.fallback_key_path = Some(key_path.into());
        self
    }

    pub fn spawn(
        self,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> io::Result<tokio::task::JoinHandle<()>> {
        if !self.config.moq.enabled {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MoQ listener requires web.moq.enabled=true",
            ));
        }
        let Some(listen) = self.config.moq.listen else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MoQ listener requires web.moq.listen",
            ));
        };

        #[cfg(feature = "moq")]
        {
            Ok(tokio::spawn(async move {
                if let Err(error) = self.run_native_moq_server(listen, shutdown).await {
                    tracing::warn!(%listen, error = %error, "MoQ listener exited");
                }
            }))
        }

        #[cfg(not(feature = "moq"))]
        {
            Ok(tokio::spawn(async move {
                tracing::warn!(
                    %listen,
                    "web.moq is enabled but binary was built without the `moq` Cargo feature"
                );
                let _ = shutdown.changed().await;
            }))
        }
    }

    #[cfg(feature = "moq")]
    async fn run_native_moq_server(
        self,
        listen: SocketAddr,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> io::Result<()> {
        let mut config = moq_native::ServerConfig::default();
        config.bind = Some(listen.to_string());
        let cert_path = self
            .config
            .moq
            .cert_path
            .clone()
            .or(self.fallback_cert_path.clone());
        let key_path = self
            .config
            .moq
            .key_path
            .clone()
            .or(self.fallback_key_path.clone());
        match (cert_path, key_path) {
            (Some(cert_path), Some(key_path)) => {
                config.tls.cert = vec![cert_path];
                config.tls.key = vec![key_path];
            }
            (None, None) => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "MoQ listener requires both web.moq.cert_path and web.moq.key_path",
                ));
            }
        }
        let mut server = config
            .init()
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        tracing::info!(%listen, "MoQ WebTransport server listening");
        loop {
            tokio::select! {
                request = server.accept() => {
                    let Some(request) = request else {
                        break;
                    };
                    let request_path = request.url().map(|url| url.path().to_string());
                    if request_path.as_deref() != Some(PATH) {
                        if let Err(error) = request.close(404).await {
                            tracing::trace!(error = %error, "failed to reject MoQ request");
                        }
                        continue;
                    }
                    let (outgoing_origin, incoming_origin) = self.moq_origins();
                    match request
                        .with_publish(outgoing_origin.consume())
                        .with_consume(incoming_origin.clone())
                        .ok()
                        .await
                    {
                        Ok(session) => {
                            let server = self.clone();
                            tokio::spawn(async move {
                                if let Err(error) = server
                                    .run_moq_session(session, outgoing_origin, incoming_origin.consume())
                                    .await
                                {
                                    tracing::trace!(error = %error, "MoQ session ended");
                                }
                            });
                        }
                        Err(error) => {
                            tracing::trace!(error = %error, "failed to accept MoQ request");
                        }
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
        Ok(())
    }

    #[cfg(feature = "moq")]
    fn moq_origins(&self) -> (moq_lite::OriginProducer, moq_lite::OriginProducer) {
        (
            moq_lite::Origin::random().produce(),
            moq_lite::Origin::random().produce(),
        )
    }

    #[cfg(feature = "moq")]
    async fn run_moq_session(
        &self,
        session: moq_lite::Session,
        outgoing_origin: moq_lite::OriginProducer,
        incoming_origin: moq_lite::OriginConsumer,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut runtime = MoqSessionRuntime::new(self.web_session_context());
        runtime
            .attach_moq(session, outgoing_origin, incoming_origin)
            .await
    }

    fn web_session_context(&self) -> WebSessionContext {
        let fallback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        WebSessionContext::new(
            self.config.clone(),
            self.authenticator.clone(),
            self.server.clone(),
            self.provisional_server_id.clone(),
            fallback.ip(),
            fallback,
            self.config.moq.listen.unwrap_or(fallback),
        )
    }
}

pub struct MoqSessionRuntime {
    context: WebSessionContext,
    client: Option<Arc<Box<Client>>>,
    outbound_rx: Option<mpsc::Receiver<Message>>,
    client_log_rx: Option<
        tokio::sync::broadcast::Receiver<
            Arc<crate::client::state_log::ClientStateBroadcastPayload>,
        >,
    >,
    channel_log_rx:
        Option<tokio::sync::broadcast::Receiver<Arc<crate::channel_repository::ChannelOperation>>>,
    voice_rx: Option<mpsc::Receiver<Bytes>>,
    channel_shadow: SessionChannelShadow,
    user_visibility: UserVisibilityState,
    inbound_voice: InboundVoiceMetadata,
    frame_numbers: crate::web::voice::RtpFrameNumberMapper,
}

impl MoqSessionRuntime {
    pub fn new(context: WebSessionContext) -> Self {
        Self {
            context,
            client: None,
            outbound_rx: None,
            client_log_rx: None,
            channel_log_rx: None,
            voice_rx: None,
            channel_shadow: HashMap::new(),
            user_visibility: UserVisibilityState::default(),
            inbound_voice: InboundVoiceMetadata::new(),
            frame_numbers: crate::web::voice::RtpFrameNumberMapper::new(),
        }
    }

    pub async fn handle_control_command(
        &mut self,
        command: ClientCommand,
    ) -> Result<Vec<ServerEvent>, String> {
        match command {
            ClientCommand::Authenticate { auth } => {
                if self.client.is_some() {
                    return Ok(vec![ServerEvent::AuthenticationRejected {
                        reason: "already authenticated".to_string(),
                    }]);
                }
                let (outbound_tx, outbound_rx) = mpsc::channel::<Message>(256);
                let result = self
                    .context
                    .authenticate(0, auth)
                    .await
                    .map_err(authentication_rejection_reason)?;
                let Some((server, client, session, display_name)) = self
                    .context
                    .allocate_authenticated_client(result, outbound_tx, WebSessionTransport::Moq)
                    .await
                else {
                    return Err("MoQ authentication is not wired to this server".to_string());
                };

                self.outbound_rx = Some(outbound_rx);
                self.voice_rx = client.take_voice_tcp_rx();
                self.client = Some(Arc::clone(&client));
                let mut events = vec![ServerEvent::Authenticated {
                    session,
                    display_name,
                }];
                events.extend(
                    initial_server_events(
                        &server,
                        &client,
                        &mut self.channel_shadow,
                        &mut self.user_visibility,
                    )
                    .await,
                );
                client
                    .set_last_channel_version(
                        server
                            .get_channels()
                            .current_version_in_server(&client.server_id()),
                    )
                    .await;
                let (_, versions) = server
                    .get_clients()
                    .snapshot_with_versions_in_server(&client.server_id())
                    .await;
                client.update_last_client_versions(&versions).await;
                self.client_log_rx = Some(server.get_clients().subscribe());
                self.channel_log_rx = Some(server.get_channels().subscribe());
                Ok(events)
            }
            ClientCommand::VoiceControl { ptt, target, epoch } => {
                self.update_voice_control(ptt, target, epoch).await;
                Ok(vec![ServerEvent::VoiceControlAck { epoch }])
            }
            command => {
                let Some(server) = self.context.server().cloned() else {
                    return Err("MoQ control command is not wired to this server".to_string());
                };
                let Some(client) = self.client.as_ref() else {
                    return Err("authentication required before control command".to_string());
                };
                match apply_control_command(&server, client, command).await? {
                    Some(event) => Ok(vec![event]),
                    None => Ok(Vec::new()),
                }
            }
        }
    }

    pub async fn disconnect_client(&mut self) {
        let Some(server) = self.context.server().cloned() else {
            self.client = None;
            return;
        };
        let Some(client) = self.client.take() else {
            return;
        };
        server
            .get_clients()
            .as_ref()
            .remove_client_in_server(&client.server_id(), client.get_session_id())
            .await;
        self.voice_rx = None;
    }

    pub async fn handle_inbound_audio_frame(&mut self, frame: MoqAudioFrame) -> Result<(), String> {
        let Some(client) = self.client.as_ref() else {
            return Err("authentication required before audio".to_string());
        };
        let Some(epoch) = self.inbound_voice.routable_epoch() else {
            return Ok(());
        };
        if !epoch.ptt && !frame.is_terminator() {
            return Ok(());
        }
        let mapped = self
            .frame_numbers
            .map_packet(0, epoch.epoch, frame.timestamp_micros() as u32)
            .frame_number;
        let audio = Audio {
            frame_number: mapped,
            ..frame.into_audio(client.get_session_id(), epoch.target)
        };
        client.push_voice_routing(audio);
        Ok(())
    }

    pub async fn drain_outbound_events(&mut self) -> Result<Vec<ServerEvent>, String> {
        let mut events = Vec::new();
        while let Some(rx) = self.outbound_rx.as_mut() {
            match rx.try_recv() {
                Ok(message) => {
                    if let Some(event) = server_event_from_message(message) {
                        events.push(event);
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err("MoQ client outbound queue closed".to_string());
                }
            }
        }
        Ok(events)
    }

    async fn update_voice_control(&mut self, ptt: bool, target: VoiceTarget, epoch: u64) {
        let target = voice_target_kind(target);
        self.inbound_voice.update_epoch(epoch, target, ptt);
        self.inbound_voice.acknowledge(epoch);
    }

    #[cfg(feature = "moq")]
    async fn attach_moq(
        &mut self,
        session: moq_lite::Session,
        outgoing_origin: moq_lite::OriginProducer,
        incoming_origin: moq_lite::OriginConsumer,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let origin = outgoing_origin;
        let mut broadcast = moq_lite::Broadcast::new().produce();
        let mut control_down = broadcast.create_track(moq_lite::Track::new(CONTROL_DOWN_TRACK))?;
        let mut catalog = broadcast.create_track(moq_lite::Track::new(CATALOG_TRACK))?;
        let max_tracks = self.context.config().moq.max_speaker_tracks.max(1);
        let mut audio_tracks = Vec::with_capacity(max_tracks as usize);
        for slot in 0..max_tracks {
            audio_tracks.push((
                slot,
                broadcast
                    .create_track(moq_lite::Track::new(MoqTrackNames::audio_down_slot(slot)))?,
            ));
        }
        origin.publish_broadcast(BROADCAST_PATH, broadcast.consume());
        let mut moq_session = session;

        let catalog_bytes = Bytes::from(
            MoqCatalog::new(&self.context.config().moq)
                .to_hang_catalog(&self.context.config().moq)
                .to_vec()?,
        );
        catalog.write_frame(catalog_bytes)?;

        let consumer = incoming_origin;
        let incoming_broadcast = consumer
            .announced_broadcast(BROADCAST_PATH)
            .await
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "MoQ client broadcast missing")
            })?;
        let mut control_up = incoming_broadcast
            .subscribe_track(&moq_lite::Track::new(CONTROL_UP_TRACK))
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "MoQ control/up track missing"))?;
        let mut audio_up = incoming_broadcast
            .subscribe_track(&moq_lite::Track::new(AUDIO_UP_MIC_TRACK))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::NotFound, "MoQ audio/up/mic track missing")
            })?;

        let mut outbound_audio: Option<mpsc::Receiver<MoqOutboundAudioEvent>> = None;
        let mut background_tick = tokio::time::interval(std::time::Duration::from_millis(25));
        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
            loop {
                tokio::select! {
                    command = read_next_json_command(&mut control_up) => {
                        let Some(command) = command? else {
                            break;
                        };
                        match self.handle_control_command(command).await {
                            Ok(events) => write_control_events(&mut control_down, events)?,
                            Err(message) => write_control_events(
                                &mut control_down,
                                vec![ServerEvent::Error { message }],
                            )?,
                        }
                        if self.client.is_some() && outbound_audio.is_none() {
                            outbound_audio = Some(self.spawn_outbound_audio_task(&audio_tracks));
                        }
                    }
                    audio = read_next_audio_frame(&mut audio_up) => {
                        let Some(audio) = audio? else {
                            break;
                        };
                        if let Err(message) = self.handle_inbound_audio_frame(audio).await {
                            write_control_events(&mut control_down, vec![ServerEvent::Error { message }])?;
                        }
                    }
                    _ = background_tick.tick() => {
                        match self.next_background_events().await {
                            Ok(events) => write_control_events(&mut control_down, events)?,
                            Err(message) => write_control_events(
                                &mut control_down,
                                vec![ServerEvent::Error { message }],
                            )?,
                        }
                    }
                    outbound = async {
                        match outbound_audio.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending::<Option<MoqOutboundAudioEvent>>().await,
                        }
                    }, if outbound_audio.is_some() => {
                        match outbound {
                            Some(MoqOutboundAudioEvent::Control(events)) => {
                                write_control_events(&mut control_down, events)?;
                            }
                            Some(MoqOutboundAudioEvent::Frame { slot, frame }) => {
                                if let Some((_, track)) = audio_tracks.iter_mut().find(|(candidate, _)| *candidate == slot) {
                                    write_audio_frame_to_track(track, &frame)?;
                                }
                            }
                            None => break,
                        }
                    }
                    result = moq_session.closed() => {
                        if let Err(error) = result {
                            tracing::trace!(error = %error, "MoQ transport session closed");
                        }
                        break;
                    }
                }
            }
            Ok(())
        }
        .await;
        self.disconnect_client().await;
        result
    }

    #[cfg(feature = "moq")]
    async fn next_background_events(&mut self) -> Result<Vec<ServerEvent>, String> {
        let mut events = self.drain_outbound_events().await?;
        if let Some(op) = recv_broadcast_now(self.channel_log_rx.as_mut()).await? {
            events.extend(self.channel_log_events(op).await?);
        }
        if let Some(payload) = recv_broadcast_now(self.client_log_rx.as_mut()).await? {
            events.extend(self.client_log_events(payload).await?);
        }
        Ok(events)
    }

    #[cfg(feature = "moq")]
    async fn channel_log_events(
        &mut self,
        op: Arc<crate::channel_repository::ChannelOperation>,
    ) -> Result<Vec<ServerEvent>, String> {
        let Some(server) = self.context.server().cloned() else {
            return Ok(Vec::new());
        };
        let Some(client) = self.client.as_ref().cloned() else {
            return Ok(Vec::new());
        };
        let last = client.get_last_channel_version().await;
        let server_id = client.server_id();
        if op.server_id != server_id || op.version <= last {
            return Ok(Vec::new());
        }
        if op.version > last + 1 {
            return self.channel_log_gap_events().await;
        }
        let messages = crate::channel_handler::convert_channel_operation_to_messages_with_shadow(
            &server,
            &client,
            &op,
            server.get_channels(),
            Some(&mut self.channel_shadow),
        )
        .await;
        let mut events = Vec::new();
        for message in messages {
            events.extend(
                message_with_synthetic_events(
                    &server,
                    &client,
                    &mut self.channel_shadow,
                    &mut self.user_visibility,
                    &server_id,
                    &message,
                )
                .await,
            );
        }
        let reconcile =
            crate::client::visibility::reconcile_all(&server, &client, &mut self.user_visibility)
                .await;
        for message in reconcile {
            events.extend(
                crate::client::visibility::sync_projected_message_with_shadow(
                    &server,
                    &client,
                    &mut self.user_visibility,
                    &mut self.channel_shadow,
                    &server_id,
                    message,
                )
                .await
                .into_iter()
                .filter_map(server_event_from_message),
            );
        }
        client.set_last_channel_version(op.version).await;
        Ok(events)
    }

    #[cfg(feature = "moq")]
    async fn channel_log_gap_events(&mut self) -> Result<Vec<ServerEvent>, String> {
        let Some(server) = self.context.server().cloned() else {
            return Ok(Vec::new());
        };
        let Some(client) = self.client.as_ref().cloned() else {
            return Ok(Vec::new());
        };
        let last = client.get_last_channel_version().await;
        let server_id = client.server_id();
        let missed = server
            .get_channels()
            .get_log_since_in_server(&server_id, last)
            .await;
        if missed.is_empty() && last > 0 {
            return Err("MoQ channel update gap is unrecoverable".to_string());
        }
        let mut events = Vec::new();
        for op in missed {
            let messages =
                crate::channel_handler::convert_channel_operation_to_messages_with_shadow(
                    &server,
                    &client,
                    &op,
                    server.get_channels(),
                    Some(&mut self.channel_shadow),
                )
                .await;
            for message in messages {
                events.extend(
                    message_with_synthetic_events(
                        &server,
                        &client,
                        &mut self.channel_shadow,
                        &mut self.user_visibility,
                        &server_id,
                        &message,
                    )
                    .await,
                );
            }
            let reconcile = crate::client::visibility::reconcile_all(
                &server,
                &client,
                &mut self.user_visibility,
            )
            .await;
            for message in reconcile {
                events.extend(
                    crate::client::visibility::sync_projected_message_with_shadow(
                        &server,
                        &client,
                        &mut self.user_visibility,
                        &mut self.channel_shadow,
                        &server_id,
                        message,
                    )
                    .await
                    .into_iter()
                    .filter_map(server_event_from_message),
                );
            }
            client.set_last_channel_version(op.version).await;
        }
        Ok(events)
    }

    #[cfg(feature = "moq")]
    async fn client_log_events(
        &mut self,
        payload: Arc<crate::client::state_log::ClientStateBroadcastPayload>,
    ) -> Result<Vec<ServerEvent>, String> {
        let Some(server) = self.context.server().cloned() else {
            return Ok(Vec::new());
        };
        let Some(client) = self.client.as_ref().cloned() else {
            return Ok(Vec::new());
        };
        let entry = &payload.entry;
        let server_id = client.server_id();
        if entry.op.server_id() != server_id {
            return Ok(Vec::new());
        }
        let last_seen = client.get_last_client_versions().await;
        let last_for_node = last_seen.get(&entry.node_id).copied().unwrap_or(0);
        if entry.version <= last_for_node {
            return Ok(Vec::new());
        }
        if entry.version > last_for_node + 1 {
            return self.client_log_gap_events().await;
        }
        if is_own_add_client(&entry.op, client.get_session_id()) {
            client.update_last_client_versions(&payload.versions).await;
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        if let Some(message) = entry.to_message(server.get_clients()).await {
            events.extend(
                message_with_synthetic_events(
                    &server,
                    &client,
                    &mut self.channel_shadow,
                    &mut self.user_visibility,
                    &server_id,
                    &message,
                )
                .await,
            );
        }
        let reconcile =
            crate::client::visibility::reconcile_all(&server, &client, &mut self.user_visibility)
                .await;
        for message in reconcile {
            events.extend(
                crate::client::visibility::sync_projected_message_with_shadow(
                    &server,
                    &client,
                    &mut self.user_visibility,
                    &mut self.channel_shadow,
                    &server_id,
                    message,
                )
                .await
                .into_iter()
                .filter_map(server_event_from_message),
            );
        }
        client.update_last_client_versions(&payload.versions).await;
        Ok(events)
    }

    #[cfg(feature = "moq")]
    async fn client_log_gap_events(&mut self) -> Result<Vec<ServerEvent>, String> {
        let Some(server) = self.context.server().cloned() else {
            return Ok(Vec::new());
        };
        let Some(client) = self.client.as_ref().cloned() else {
            return Ok(Vec::new());
        };
        let last_seen = client.get_last_client_versions().await;
        let server_id = client.server_id();
        let (missed, versions) = server
            .get_clients()
            .replay_since_in_server(&server_id, &last_seen)
            .await
            .map_err(|()| "MoQ client update gap is unrecoverable".to_string())?;
        let mut events = Vec::new();
        for message in missed {
            events.extend(
                message_with_synthetic_events(
                    &server,
                    &client,
                    &mut self.channel_shadow,
                    &mut self.user_visibility,
                    &server_id,
                    &message,
                )
                .await,
            );
        }
        let reconcile =
            crate::client::visibility::reconcile_all(&server, &client, &mut self.user_visibility)
                .await;
        for message in reconcile {
            events.extend(
                crate::client::visibility::sync_projected_message_with_shadow(
                    &server,
                    &client,
                    &mut self.user_visibility,
                    &mut self.channel_shadow,
                    &server_id,
                    message,
                )
                .await
                .into_iter()
                .filter_map(server_event_from_message),
            );
        }
        client.update_last_client_versions(&versions).await;
        Ok(events)
    }

    #[cfg(feature = "moq")]
    fn spawn_outbound_audio_task(
        &mut self,
        tracks: &[(u32, moq_lite::TrackProducer)],
    ) -> mpsc::Receiver<MoqOutboundAudioEvent> {
        let (tx, rx) = mpsc::channel(256);
        let Some(client) = self.client.as_ref().cloned() else {
            return rx;
        };
        let Some(server) = self.context.server().cloned() else {
            return rx;
        };
        let Some(mut voice_rx) = self.voice_rx.take() else {
            return rx;
        };
        let slots: Vec<_> = tracks.iter().map(|(slot, _)| *slot).collect();
        tokio::spawn(async move {
            let mut speakers = SsrcAllocator::from_ssrcs(
                slots
                    .iter()
                    .map(|slot| MOQ_FIRST_DOWN_SLOT_SSRC.saturating_add(*slot)),
            );
            let mut active: HashMap<u32, MoqActiveSpeaker> = HashMap::new();
            let mut next_epoch = 1u64;
            while let Some(raw) = voice_rx.recv().await {
                let Ok(audio) = Audio::decode(&raw, None) else {
                    continue;
                };
                let Some(frame) = MoqAudioFrame::from_audio(&audio) else {
                    continue;
                };
                let Some(sender_session_id) = audio.sender_session.map(u32::from) else {
                    continue;
                };
                if sender_session_id == u32::from(client.get_session_id()) {
                    continue;
                }
                if !active.contains_key(&sender_session_id) {
                    let epoch = next_epoch;
                    next_epoch = next_epoch.saturating_add(1);
                    let Ok(assignment) = speakers.assign(sender_session_id, epoch) else {
                        continue;
                    };
                    let slot = assignment.ssrc.saturating_sub(MOQ_FIRST_DOWN_SLOT_SSRC);
                    let context = outbound_context(&audio);
                    let channel_id = outbound_speaker_channel(&server, sender_session_id)
                        .await
                        .unwrap_or_else(|| client.get_current_channel_id());
                    let events = vec![
                        ServerEvent::SpeakerAssigned(SpeakerAssigned {
                            ssrc: assignment.ssrc,
                            speaker_session: assignment.speaker_session,
                            track_id: MoqTrackNames::audio_down_slot(slot),
                            epoch: assignment.epoch,
                        }),
                        ServerEvent::VoiceSegmentStart(VoiceSegment {
                            ssrc: assignment.ssrc,
                            speaker_session: assignment.speaker_session,
                            context: context.clone(),
                            channel_id,
                            rtp_timestamp: audio.frame_number as u32,
                            epoch: assignment.epoch,
                        }),
                    ];
                    if tx
                        .send(MoqOutboundAudioEvent::Control(events))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    active.insert(
                        sender_session_id,
                        MoqActiveSpeaker {
                            speaker_session: assignment.speaker_session,
                            slot,
                            ssrc: assignment.ssrc,
                            epoch: assignment.epoch,
                            context,
                            channel_id,
                        },
                    );
                }

                let Some(current) = active.get(&sender_session_id).cloned() else {
                    continue;
                };
                if !frame.payload().is_empty()
                    && tx
                        .send(MoqOutboundAudioEvent::Frame {
                            slot: current.slot,
                            frame: frame.clone(),
                        })
                        .await
                        .is_err()
                {
                    break;
                }
                if frame.is_terminator() {
                    active.remove(&sender_session_id);
                    speakers.release(sender_session_id);
                    let event = ServerEvent::VoiceSegmentEnd(VoiceSegment {
                        ssrc: current.ssrc,
                        speaker_session: current.speaker_session,
                        context: current.context,
                        channel_id: current.channel_id,
                        rtp_timestamp: audio.frame_number as u32,
                        epoch: current.epoch,
                    });
                    if tx
                        .send(MoqOutboundAudioEvent::Control(vec![event]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
        rx
    }
}

#[cfg(feature = "moq")]
async fn read_next_json_command(
    track: &mut moq_lite::TrackConsumer,
) -> Result<Option<ClientCommand>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(bytes) = track.read_frame().await? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes)?;
    Ok(Some(decode_client_command(text)?))
}

#[cfg(feature = "moq")]
async fn read_next_audio_frame(
    track: &mut moq_lite::TrackConsumer,
) -> Result<Option<MoqAudioFrame>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(bytes) = track.read_frame().await? else {
        return Ok(None);
    };
    if bytes.starts_with(MOQ_AUDIO_MAGIC) {
        return Ok(Some(MoqAudioFrame::decode(bytes)?));
    }
    Ok(Some(MoqAudioFrame::from_hang_frame(
        hang::container::Frame::decode(bytes)?,
        false,
    )))
}

#[cfg(feature = "moq")]
fn write_control_events(
    track: &mut moq_lite::TrackProducer,
    events: Vec<ServerEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for event in events {
        track.write_frame(Bytes::from(encode_server_event(&event)?))?;
    }
    Ok(())
}

#[cfg(feature = "moq")]
fn write_audio_frame_to_track(
    track: &mut moq_lite::TrackProducer,
    frame: &MoqAudioFrame,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut group = track.append_group()?;
    frame.to_hang_frame().encode(&mut group)?;
    group.finish()?;
    Ok(())
}

#[cfg(feature = "moq")]
async fn recv_broadcast_now<T: Clone>(
    rx: Option<&mut tokio::sync::broadcast::Receiver<Arc<T>>>,
) -> Result<Option<Arc<T>>, String> {
    let Some(rx) = rx else {
        return Ok(None);
    };
    match rx.try_recv() {
        Ok(item) => Ok(Some(item)),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty) => Ok(None),
        Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => Ok(None),
        Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
            Err("MoQ update stream closed".to_string())
        }
    }
}

#[cfg(feature = "moq")]
async fn message_with_synthetic_events(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    server_id: &str,
    message: &Message,
) -> Vec<ServerEvent> {
    crate::client::visibility::project_message_with_shadow(
        server,
        client,
        user_visibility,
        channel_shadow,
        server_id,
        message,
    )
    .await
    .into_iter()
    .filter_map(server_event_from_message)
    .collect()
}

#[cfg(feature = "moq")]
#[derive(Debug, Clone)]
enum MoqOutboundAudioEvent {
    Control(Vec<ServerEvent>),
    Frame { slot: u32, frame: MoqAudioFrame },
}

#[cfg(feature = "moq")]
#[derive(Debug, Clone)]
struct MoqActiveSpeaker {
    speaker_session: u32,
    slot: u32,
    ssrc: u32,
    epoch: u64,
    context: String,
    channel_id: u32,
}

fn authentication_rejection_reason(rejection: crate::api::AuthenticationRejection) -> String {
    match rejection {
        crate::api::AuthenticationRejection::WrongPassword => "wrong password",
        crate::api::AuthenticationRejection::NoSuchUser => "no such user",
        crate::api::AuthenticationRejection::RetryLater => "authenticator temporarily unavailable",
    }
    .to_string()
}

fn voice_target_kind(target: VoiceTarget) -> VoiceTargetKind {
    match target {
        VoiceTarget::Normal => VoiceTargetKind::Normal,
        VoiceTarget::ServerLoopback => VoiceTargetKind::ServerLoopback,
        VoiceTarget::Slot(slot) => VoiceTargetKind::Slot(slot),
    }
}

fn is_own_add_client(op: &ClientStateOperation, session_id: ClientSessionIdentifier) -> bool {
    matches!(op, ClientStateOperation::AddClient { session_id: id, .. } if *id == session_id)
}

fn audio_target(target: VoiceTargetKind) -> crate::messages::encoder::AudioTarget {
    match target {
        VoiceTargetKind::Normal => crate::messages::encoder::AudioTarget::Normal,
        VoiceTargetKind::ServerLoopback => crate::messages::encoder::AudioTarget::ServerLoopback,
        VoiceTargetKind::Slot(slot) => crate::messages::encoder::AudioTarget::VoiceTarget(slot),
    }
}

fn outbound_context(audio: &Audio) -> String {
    match audio.target {
        crate::messages::encoder::AudioTarget::Normal => "normal".to_string(),
        crate::messages::encoder::AudioTarget::ServerLoopback => "loopback".to_string(),
        crate::messages::encoder::AudioTarget::VoiceTarget(slot) => format!("target:{slot}"),
    }
}

#[cfg(feature = "moq")]
async fn outbound_speaker_channel(server: &Arc<Box<Server>>, speaker_session: u32) -> Option<u32> {
    let client = server
        .get_clients()
        .get_client(ClientSessionIdentifier::from(speaker_session))
        .await?;
    Some(client.get_current_channel_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    use crate::api::{AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection};
    use crate::client::ClientTransportKind;
    use crate::config::{Config, UdpPingUserCountScope, WebAuthConfig, WebAuthMode};
    use crate::localization::Language;
    use crate::messages::encoder::AudioContext;
    use crate::web::protocol::AuthRequest;

    #[test]
    fn track_names_are_stable() {
        let names = MoqTrackNames::default();
        assert_eq!(names.control_up(), "control/up");
        assert_eq!(names.control_down(), "control/down");
        assert_eq!(names.audio_up_mic(), "audio/up/mic");
        assert_eq!(names.catalog(), "catalog.json");
        assert_eq!(MoqTrackNames::audio_down_slot(3), "audio/down/slot/3");
    }

    #[cfg(feature = "moq")]
    #[test]
    fn catalog_track_matches_hang_default() {
        assert_eq!(CATALOG_TRACK, hang::Catalog::DEFAULT_NAME);
    }

    #[test]
    fn audio_frame_roundtrip_preserves_payload_timestamp_and_terminator() {
        let frame = MoqAudioFrame {
            timestamp_micros: 42_000,
            payload: Bytes::from_static(b"opus"),
            terminator: true,
        };
        let decoded = MoqAudioFrame::decode(frame.encode()).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn catalog_advertises_opus_speaker_tracks() {
        let config = WebMoqConfig {
            enabled: true,
            listen: None,
            public_url: None,
            cert_path: None,
            key_path: None,
            max_speaker_tracks: 2,
            audio_bitrate: 48_000,
        };
        let catalog = MoqCatalog::new(&config);
        let audio = catalog
            .tracks()
            .iter()
            .filter(|track| track.kind() == MoqTrackKind::Audio)
            .collect::<Vec<_>>();
        assert_eq!(audio.len(), 3);
        assert!(audio.iter().any(|track| track.name() == "audio/up/mic"));
        assert!(audio
            .iter()
            .any(|track| track.name() == "audio/down/slot/0"));
        assert!(audio
            .iter()
            .any(|track| track.name() == "audio/down/slot/1"));
        assert!(audio.iter().all(|track| track.codec() == Some("opus")));
    }

    #[test]
    fn audio_frame_maps_to_and_from_voice_audio() {
        let session = ClientSessionIdentifier::new(1, 7).unwrap();
        let frame = MoqAudioFrame::new(12_345, Bytes::from_static(b"opus-data"));
        let audio = frame
            .clone()
            .into_audio(session, VoiceTargetKind::ServerLoopback);

        assert_eq!(audio.sender_session, Some(session));
        assert_eq!(audio.frame_number, 12_345);
        assert_eq!(
            audio.target,
            crate::messages::encoder::AudioTarget::ServerLoopback
        );
        let AudioPayload::Opus(opus) = &audio.audio_payload else {
            panic!("expected opus payload");
        };
        assert_eq!(opus.frame, Bytes::from_static(b"opus-data"));
        assert!(!opus.is_terminator);

        assert_eq!(MoqAudioFrame::from_audio(&audio), Some(frame));
    }

    #[tokio::test]
    async fn control_auth_allocates_normal_moq_client() {
        let server = test_server(TestAuthenticator).await;
        let context = test_session_context(Arc::clone(&server));
        let mut runtime = MoqSessionRuntime::new(context);

        let events = runtime
            .handle_control_command(ClientCommand::Authenticate {
                auth: AuthRequest::Password {
                    username: "alice".to_string(),
                    password: "secret".to_string(),
                },
            })
            .await
            .expect("authenticate");

        let session = events
            .iter()
            .find_map(|event| match event {
                ServerEvent::Authenticated { session, .. } => Some(*session),
                _ => None,
            })
            .expect("authenticated event");
        assert_ne!(session, 0);
        assert_eq!(server.get_clients().local_len().await, 1);

        let client = server
            .get_clients()
            .get_client(ClientSessionIdentifier::from(session))
            .await
            .expect("allocated client");
        assert_eq!(client.transport_kind(), ClientTransportKind::Moq);
        assert!(client.is_authenticated());
        assert!(events
            .iter()
            .any(|event| matches!(event, ServerEvent::ServerSync(_))));
    }

    #[tokio::test]
    async fn control_commands_hit_existing_handlers_after_auth() {
        let server = test_server(TestAuthenticator).await;
        server
            .get_channels()
            .create_channel(crate::channels::Channel::new(1, "Lobby", 0, 0, Some(0)))
            .await
            .unwrap();
        let context = test_session_context(Arc::clone(&server));
        let mut runtime = MoqSessionRuntime::new(context);

        let auth_events = runtime
            .handle_control_command(ClientCommand::Authenticate {
                auth: AuthRequest::Password {
                    username: "alice".to_string(),
                    password: "secret".to_string(),
                },
            })
            .await
            .expect("authenticate");
        let session = auth_events
            .iter()
            .find_map(|event| match event {
                ServerEvent::Authenticated { session, .. } => Some(*session),
                _ => None,
            })
            .expect("authenticated event");

        runtime
            .handle_control_command(ClientCommand::JoinChannel { channel_id: 1 })
            .await
            .expect("join channel");

        let client = server
            .get_clients()
            .get_client(ClientSessionIdentifier::from(session))
            .await
            .expect("allocated client");
        assert_eq!(client.get_current_channel_id(), 1);
    }

    #[tokio::test]
    async fn inbound_audio_waits_for_acknowledged_voice_epoch() {
        let context = test_session_context_without_server();
        let mut runtime = MoqSessionRuntime::new(context);
        let (outbound_tx, _outbound_rx) = mpsc::channel::<Message>(8);
        let client = Arc::new(Client::new_moq_gateway_in_server(
            crate::types::DEFAULT_SERVER_ID.to_string(),
            ClientSessionIdentifier::new(1, 77).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64740),
            outbound_tx,
        ));
        let mut voice_rx = client.take_voice_routing_rx().expect("voice rx");
        runtime.client = Some(Arc::clone(&client));

        runtime
            .handle_inbound_audio_frame(MoqAudioFrame::new(100, Bytes::from_static(b"ignored")))
            .await
            .expect("audio before ptt");
        assert!(voice_rx.try_recv().is_err());

        let ack = runtime
            .handle_control_command(ClientCommand::VoiceControl {
                ptt: true,
                target: VoiceTarget::Normal,
                epoch: 9,
            })
            .await
            .expect("voice control");
        assert_eq!(ack, vec![ServerEvent::VoiceControlAck { epoch: 9 }]);

        runtime
            .handle_inbound_audio_frame(MoqAudioFrame::new(101, Bytes::from_static(b"opus")))
            .await
            .expect("audio after ptt");
        let routed = voice_rx.try_recv().expect("routed voice").decoded_audio;
        assert_eq!(routed.sender_session, Some(client.get_session_id()));
        let AudioPayload::Opus(opus) = routed.audio_payload else {
            panic!("expected opus payload");
        };
        assert_eq!(opus.frame, Bytes::from_static(b"opus"));
    }

    #[tokio::test]
    async fn inbound_audio_accepts_terminator_after_ptt_off_ack() {
        let context = test_session_context_without_server();
        let mut runtime = MoqSessionRuntime::new(context);
        let (outbound_tx, _outbound_rx) = mpsc::channel::<Message>(8);
        let client = Arc::new(Client::new_moq_gateway_in_server(
            crate::types::DEFAULT_SERVER_ID.to_string(),
            ClientSessionIdentifier::new(1, 78).unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64740),
            outbound_tx,
        ));
        let mut voice_rx = client.take_voice_routing_rx().expect("voice rx");
        runtime.client = Some(Arc::clone(&client));

        runtime
            .handle_control_command(ClientCommand::VoiceControl {
                ptt: true,
                target: VoiceTarget::Normal,
                epoch: 1,
            })
            .await
            .expect("ptt on");
        runtime
            .handle_inbound_audio_frame(MoqAudioFrame::new(10, Bytes::from_static(b"opus")))
            .await
            .expect("audio");
        let _ = voice_rx.try_recv().expect("routed voice");

        runtime
            .handle_control_command(ClientCommand::VoiceControl {
                ptt: false,
                target: VoiceTarget::Normal,
                epoch: 2,
            })
            .await
            .expect("ptt off");
        runtime
            .handle_inbound_audio_frame(MoqAudioFrame::terminator(11))
            .await
            .expect("terminator after ptt off");

        let routed = voice_rx
            .try_recv()
            .expect("routed terminator")
            .decoded_audio;
        let AudioPayload::Opus(opus) = routed.audio_payload else {
            panic!("expected opus payload");
        };
        assert!(opus.is_terminator);
    }

    #[cfg(feature = "moq")]
    #[tokio::test]
    async fn outbound_audio_task_maps_tcp_voice_to_speaker_slot_events_and_hang_frames() {
        let server = test_server(TestAuthenticator).await;
        let context = test_session_context(Arc::clone(&server));
        let mut runtime = MoqSessionRuntime::new(context);
        let auth_events = runtime
            .handle_control_command(ClientCommand::Authenticate {
                auth: AuthRequest::Password {
                    username: "alice".to_string(),
                    password: "secret".to_string(),
                },
            })
            .await
            .expect("authenticate");
        let moq_session = auth_events
            .iter()
            .find_map(|event| match event {
                ServerEvent::Authenticated { session, .. } => Some(*session),
                _ => None,
            })
            .expect("authenticated event");
        let moq_client = server
            .get_clients()
            .get_client(ClientSessionIdentifier::from(moq_session))
            .await
            .expect("allocated client");
        let tracks = vec![(0, moq_lite::Track::new("audio/down/slot/0").produce())];
        let mut outbound = runtime.spawn_outbound_audio_task(&tracks);

        let speaker_session = ClientSessionIdentifier::new(1, 42).unwrap();
        let frame = Audio {
            target: crate::messages::encoder::AudioTarget::Normal,
            sender_session: Some(speaker_session),
            frame_number: 90_001,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::from_static(b"opus-frame"),
                is_terminator: false,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Protobuf,
        };
        moq_client
            .try_enqueue_voice_tcp(frame.encode(AudioContext::Normal, PacketFormat::Protobuf));
        let speaker_session_wire = u32::from(speaker_session);

        let first = tokio::time::timeout(std::time::Duration::from_secs(1), outbound.recv())
            .await
            .expect("control event")
            .expect("outbound control");
        let MoqOutboundAudioEvent::Control(events) = first else {
            panic!("expected speaker metadata first");
        };
        assert_eq!(
            events,
            vec![
                ServerEvent::SpeakerAssigned(SpeakerAssigned {
                    ssrc: 1,
                    speaker_session: speaker_session_wire,
                    track_id: "audio/down/slot/0".to_string(),
                    epoch: 1,
                }),
                ServerEvent::VoiceSegmentStart(VoiceSegment {
                    ssrc: 1,
                    speaker_session: speaker_session_wire,
                    context: "normal".to_string(),
                    channel_id: 0,
                    rtp_timestamp: 90_001,
                    epoch: 1,
                }),
            ]
        );

        let second = tokio::time::timeout(std::time::Duration::from_secs(1), outbound.recv())
            .await
            .expect("audio frame")
            .expect("outbound audio");
        let MoqOutboundAudioEvent::Frame { slot, frame } = second else {
            panic!("expected slot audio frame");
        };
        assert_eq!(slot, 0);
        assert_eq!(
            frame,
            MoqAudioFrame::new(90_001, Bytes::from_static(b"opus-frame"))
        );

        let terminator = Audio {
            target: crate::messages::encoder::AudioTarget::Normal,
            sender_session: Some(speaker_session),
            frame_number: 90_002,
            audio_payload: AudioPayload::Opus(OpusPayload {
                frame: Bytes::new(),
                is_terminator: true,
            }),
            positional_data: None,
            volume_adjustment: 1.0,
            format: PacketFormat::Protobuf,
        };
        moq_client
            .try_enqueue_voice_tcp(terminator.encode(AudioContext::Normal, PacketFormat::Protobuf));

        let end = tokio::time::timeout(std::time::Duration::from_secs(1), outbound.recv())
            .await
            .expect("segment end")
            .expect("outbound end");
        let MoqOutboundAudioEvent::Control(events) = end else {
            panic!("expected segment end metadata");
        };
        assert_eq!(
            events,
            vec![ServerEvent::VoiceSegmentEnd(VoiceSegment {
                ssrc: 1,
                speaker_session: speaker_session_wire,
                context: "normal".to_string(),
                channel_id: 0,
                rtp_timestamp: 90_002,
                epoch: 1,
            })]
        );
    }

    #[cfg(feature = "moq")]
    #[tokio::test]
    async fn outbound_audio_track_writes_hang_frame_bytes() {
        let mut track = moq_lite::Track::new("audio/down/slot/0").produce();
        let mut consumer = track.consume();
        let frame = MoqAudioFrame::new(12_345, Bytes::from_static(b"opus"));

        write_audio_frame_to_track(&mut track, &frame).expect("write hang frame");

        let bytes = tokio::time::timeout(std::time::Duration::from_secs(1), consumer.read_frame())
            .await
            .expect("read frame")
            .expect("track read")
            .expect("frame bytes");
        let decoded = hang::container::Frame::decode(bytes).expect("decode hang frame");
        assert_eq!(MoqAudioFrame::from_hang_frame(decoded, false), frame);
    }

    struct TestAuthenticator;

    #[async_trait::async_trait]
    impl Authenticator for TestAuthenticator {
        async fn authenticate(
            &self,
            username: &str,
            password: Option<&str>,
            auxiliary_data: &AuthenticateAuxiliaryData,
        ) -> Result<AuthenticateResult, AuthenticationRejection> {
            assert_eq!(auxiliary_data.session_id, 0);
            assert_eq!(auxiliary_data.ip_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
            if username != "alice" {
                return Err(AuthenticationRejection::NoSuchUser);
            }
            if password != Some("secret") {
                return Err(AuthenticationRejection::WrongPassword);
            }
            Ok(AuthenticateResult {
                user_id: Some(7),
                display_name: Some("Alice".to_string()),
                groups: vec!["web".to_string()],
                virtual_server_id: None,
                language: Language::default(),
                texture_url: None,
                comment_url: None,
            })
        }
    }

    async fn test_server<A: Authenticator>(authenticator: A) -> Arc<Box<Server>> {
        install_default_provider();
        let (cert_path, key_path) = test_cert_paths();
        Server::new(test_config(cert_path, key_path), authenticator)
            .await
            .expect("server")
    }

    fn test_session_context(server: Arc<Box<Server>>) -> WebSessionContext {
        let mut context = test_session_context_without_server();
        context = WebSessionContext::new(
            context.config().clone(),
            Some(Arc::new(TestAuthenticator)),
            Some(server),
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64740),
        );
        context
    }

    fn test_session_context_without_server() -> WebSessionContext {
        let mut config = WebConfig::default();
        config.auth = WebAuthConfig {
            modes: vec![WebAuthMode::Password],
            password_enabled: true,
            sso: Default::default(),
        };
        WebSessionContext::new(
            config,
            Some(Arc::new(TestAuthenticator)),
            None,
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64740),
        )
    }

    fn install_default_provider() {
        static CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();
        CRYPTO_PROVIDER.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn test_cert_paths() -> (PathBuf, PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap().into_path();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    fn test_config(cert_path: PathBuf, key_path: PathBuf) -> Config {
        Config {
            node_id: 1,
            listen: "127.0.0.1:0".to_string(),
            server_entrypoints: Vec::new(),
            register_name: "test".to_string(),
            register_password: None,
            register_url: None,
            register_hostname: None,
            register_location: None,
            cert_path: cert_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
            send_version: false,
            send_build_info: false,
            send_os_info: false,
            server_protocol_version: crate::constants::APP_PROTO_VER,
            allowed_proxies: Vec::new(),
            min_client_version: 0,
            max_users: 100,
            welcome_text: None,
            max_bandwidth: 72_000,
            allow_html: true,
            max_text_message_length: 5_000,
            max_image_message_length: 131_072,
            default_channel: 0,
            cert_required: false,
            blob_storage_dir: None,
            channel_log_max_entries: 10_000,
            client_log_max_entries: 10_000,
            channel_snapshot_every_ops: 10,
            channel_snapshot_every_secs: 60,
            channel_wal_compaction_expire_count: 2_000,
            udp_voice_enabled: false,
            udp_ping_enabled: false,
            udp_ping_user_count_scope: UdpPingUserCountScope::Cluster,
            udp_channel_size: 2_048,
            client_idle_timeout_secs: 30,
            pending_delete_timeout_ms: 5_000,
            required_groups: Vec::new(),
            send_permission_info: false,
            hide_users_without_traverse: false,
            s2s: crate::config::S2sConfig::default(),
            web: WebConfig::default(),
        }
    }
}
