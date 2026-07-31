use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::peer::{PeerSignal, WebRtcPeer};
use crate::protocol::{
    AuthRequest, ClientCommand, ServerEvent, VoiceTarget, WebChannelState, WebCodecVersion,
    WebGatewayConfig, WebMoqGatewayConfig, WebPermissionDenied, WebServerConfig, WebServerSync,
    WebTransportKind, WebUserRemove, WebUserState, WebVolumeAdjustment, encode_server_event,
};
use crate::session::client_is_current;
use crate::simd;
use shitspeak_auth::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
    canonical_authenticator_ip,
};
use shitspeak_runtime::channel_handler::{ChannelTreeShadow, SessionChannelShadow};
use shitspeak_runtime::client::client_session_identifier::ClientSessionIdentifier;
use shitspeak_runtime::client::state_log::{ClientStateLogEntry, ClientStateOperation};
use shitspeak_runtime::client::user_info::Credential;
use shitspeak_runtime::client::visibility::UserVisibilityState;
use shitspeak_runtime::client::{AsyncMessageHandlerExt, Client};
use shitspeak_runtime::messages::Message;
use shitspeak_runtime::messages::encoder::{ChannelRemove, CodecVersion, ServerConfig, ServerSync};
use shitspeak_runtime::server::Server;
use shitspeak_runtime_config::{WebAuthMode, WebConfig};

pub const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
pub const ALPN_MUMBLE: &[u8] = b"mumble";

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_WEBSOCKET_PAYLOAD_BYTES: usize = 64 * 1024;
const WEBSOCKET_ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const DEFAULT_WEB_SESSION_ID: u32 = 0;

#[derive(Clone)]
pub struct SignalingServer {
    config: WebConfig,
    authenticator: Option<Arc<dyn Authenticator>>,
    server: Option<Arc<Box<Server>>>,
    provisional_server_id: Option<String>,
}

impl SignalingServer {
    pub fn new(config: WebConfig) -> Self {
        Self {
            config,
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

    pub fn with_provisional_server_id(mut self, server_id: String) -> Self {
        self.provisional_server_id = Some(server_id);
        self
    }

    pub fn spawn(
        self,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> io::Result<tokio::task::JoinHandle<()>> {
        let Some(listen) = self.config.listen else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "separate web signaling listener requires web.listen",
            ));
        };
        let server = Arc::new(self);
        let listener = std::net::TcpListener::bind(listen)?;
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;

        Ok(tokio::spawn(async move {
            tracing::info!("Web signaling server listening on {listen}");
            loop {
                let (stream, peer) = tokio::select! {
                    result = listener.accept() => match result {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("web signaling accept error: {e}");
                            continue;
                        }
                    },
                    _ = shutdown.changed() => break,
                };

                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    if let Err(e) = server
                        .handle_stream_with_peer(stream, peer.ip(), peer, listen, None, false)
                        .await
                    {
                        tracing::trace!(%peer, error = %e, "web signaling connection failed");
                    }
                });
            }
        }))
    }

    pub async fn handle_stream<S>(&self, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        self.handle_stream_with_peer(stream, peer.ip(), peer, peer, None, false)
            .await
    }

    pub async fn handle_stream_with_peer<S>(
        &self,
        mut stream: S,
        real_ip: IpAddr,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        tls_ja4: Option<String>,
        uses_proxy_protocol: bool,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.config.enabled {
            write_response(
                &mut stream,
                Status::ServiceUnavailable,
                "application/json",
                br#"{"error":"web signaling is disabled"}"#,
            )
            .await?;
            return Ok(());
        }

        let mut buf = Bytes::new();
        let mut scratch = [0u8; 1024];
        loop {
            let n = stream.read(&mut scratch).await?;
            if n == 0 {
                return Ok(());
            }
            let next_len = buf.len() + n;
            if next_len > MAX_REQUEST_BYTES {
                write_response(
                    &mut stream,
                    Status::PayloadTooLarge,
                    "text/plain; charset=utf-8",
                    b"request too large",
                )
                .await?;
                return Ok(());
            }

            let mut next = Vec::with_capacity(next_len);
            next.extend_from_slice(&buf);
            next.extend_from_slice(&scratch[..n]);
            buf = Bytes::from(next);

            if find_header_end(&buf).is_some() {
                break;
            }
        }

        let request = match HttpRequest::parse(&buf) {
            Ok(request) => request,
            Err(()) => {
                write_response(
                    &mut stream,
                    Status::BadRequest,
                    "text/plain; charset=utf-8",
                    b"bad request",
                )
                .await?;
                return Ok(());
            }
        };
        let websocket_initial_bytes = request.websocket_initial_bytes().to_vec();
        let Some(first_line) = request.first_line() else {
            write_response(
                &mut stream,
                Status::BadRequest,
                "text/plain; charset=utf-8",
                b"bad request",
            )
            .await?;
            return Ok(());
        };
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default();

        match (method, path) {
            ("GET", "/health") | ("GET", "/web/health") => {
                write_response(
                    &mut stream,
                    Status::Ok,
                    "application/json",
                    br#"{"status":"ok"}"#,
                )
                .await?;
            }
            ("GET", "/web/signaling") => {
                if let Some(key) = websocket_upgrade_key(&request) {
                    write_websocket_upgrade_response(&mut stream, key).await?;
                    let context = SignalingContext::new(
                        self.config.clone(),
                        self.authenticator.clone(),
                        self.server.clone(),
                        self.provisional_server_id.clone(),
                        real_ip,
                        peer_addr,
                        local_addr,
                        tls_ja4.clone(),
                        uses_proxy_protocol,
                    );
                    run_signaling_websocket(stream, websocket_initial_bytes, context).await?;
                } else {
                    write_response(
                        &mut stream,
                        Status::BadRequest,
                        "application/json",
                        br#"{"error":"websocket upgrade required"}"#,
                    )
                    .await?;
                }
            }
            _ => {
                write_response(
                    &mut stream,
                    Status::NotFound,
                    "application/json",
                    br#"{"error":"not found"}"#,
                )
                .await?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum Status {
    Ok,
    BadRequest,
    NotFound,
    PayloadTooLarge,
    ServiceUnavailable,
}

impl Status {
    fn line(self) -> &'static str {
        match self {
            Status::Ok => "200 OK",
            Status::BadRequest => "400 Bad Request",
            Status::NotFound => "404 Not Found",
            Status::PayloadTooLarge => "413 Payload Too Large",
            Status::ServiceUnavailable => "503 Service Unavailable",
        }
    }
}

struct HttpRequest<'a> {
    buf: &'a [u8],
    header_end: usize,
    lines: std::str::Lines<'a>,
}

impl<'a> HttpRequest<'a> {
    fn parse(buf: &'a [u8]) -> Result<Self, ()> {
        let header_end = find_header_end(buf).ok_or(())?;
        let request = std::str::from_utf8(&buf[..header_end]).map_err(|_| ())?;
        Ok(Self {
            buf,
            header_end,
            lines: request.lines(),
        })
    }

    fn first_line(&self) -> Option<&'a str> {
        self.lines.clone().next()
    }

    fn header(&self, name: &str) -> Option<&'a str> {
        self.lines.clone().skip(1).find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn websocket_initial_bytes(&self) -> &'a [u8] {
        let body_start = self.header_end + 4;
        self.buf.get(body_start..).unwrap_or_default()
    }
}

async fn write_response(
    stream: &mut (impl AsyncWrite + Unpin),
    status: Status,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        status.line(),
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

async fn write_websocket_upgrade_response(
    stream: &mut (impl AsyncWrite + Unpin),
    key: &str,
) -> io::Result<()> {
    let accept = websocket_accept_key(key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         upgrade: websocket\r\n\
         connection: Upgrade\r\n\
         sec-websocket-accept: {accept}\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes()).await
}

fn websocket_upgrade_key<'a>(request: &HttpRequest<'a>) -> Option<&'a str> {
    let upgrade = request.header("upgrade")?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return None;
    }

    let connection = request.header("connection")?;
    if !connection
        .split(',')
        .any(|value| value.trim().eq_ignore_ascii_case("upgrade"))
    {
        return None;
    }

    let version = request.header("sec-websocket-version")?;
    if version.trim() != "13" {
        return None;
    }

    let key = request.header("sec-websocket-key")?;
    (!key.is_empty()).then_some(key)
}

fn websocket_accept_key(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + WEBSOCKET_ACCEPT_GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(WEBSOCKET_ACCEPT_GUID.as_bytes());
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64::engine::general_purpose::STANDARD.encode(hash.as_ref())
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SignalingRequest {
    Offer {
        sdp: String,
        #[serde(default)]
        speaker_slots: Option<u32>,
    },
    IceCandidate {
        candidate: serde_json::Value,
    },
    Authenticate {
        auth: AuthRequest,
    },
    JoinChannel {
        channel_id: u32,
    },
    SendText {
        text: String,
    },
    SetMute {
        muted: bool,
    },
    SetDeaf {
        deafened: bool,
    },
    VoiceControl {
        ptt: bool,
        #[serde(default)]
        target: Option<VoiceTarget>,
        epoch: u64,
    },
}

#[derive(Clone)]
struct SignalingContext {
    config: WebConfig,
    authenticator: Option<Arc<dyn Authenticator>>,
    server: Option<Arc<Box<Server>>>,
    provisional_server_id: String,
    real_ip: IpAddr,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    tls_ja4: Option<String>,
    uses_proxy_protocol: bool,
}

impl SignalingContext {
    fn new(
        config: WebConfig,
        authenticator: Option<Arc<dyn Authenticator>>,
        server: Option<Arc<Box<Server>>>,
        provisional_server_id: Option<String>,
        real_ip: IpAddr,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        tls_ja4: Option<String>,
        uses_proxy_protocol: bool,
    ) -> Self {
        Self {
            config,
            authenticator,
            server,
            provisional_server_id: provisional_server_id
                .unwrap_or_else(shitspeak_runtime::types::default_server_id),
            real_ip,
            peer_addr,
            local_addr,
            tls_ja4,
            uses_proxy_protocol,
        }
    }

    fn auxiliary_data(&self, session_id: u32) -> AuthenticateAuxiliaryData {
        let _ = (self.peer_addr, self.local_addr);
        AuthenticateAuxiliaryData {
            auth_session_id: None,
            certificate_hash: None,
            session_id,
            ip_address: canonical_authenticator_ip(self.real_ip),
            tls_ja4: self.tls_ja4.clone(),
            uses_proxy_protocol: self.uses_proxy_protocol,
            version: None,
            client_name: Some("shitspeak-web".to_string()),
            os_name: Some("browser".to_string()),
            os_version: None,
        }
    }

    fn requires_authentication(&self) -> bool {
        (self.config.auth.password_enabled
            && self.config.auth.modes.contains(&WebAuthMode::Password))
            || self.config.auth.modes.contains(&WebAuthMode::Sso)
    }
}

struct SignalingSession {
    authenticated: bool,
    session_id: u32,
    gateway_config_sent: bool,
    client: Option<Arc<Box<Client>>>,
    outbound_rx: Option<tokio::sync::mpsc::Receiver<Message>>,
    client_log_rx: Option<
        tokio::sync::broadcast::Receiver<
            Arc<shitspeak_runtime::client::state_log::ClientStateBroadcastPayload>,
        >,
    >,
    channel_log_rx:
        Option<tokio::sync::broadcast::Receiver<Arc<shitspeak_state::ChannelOperation>>>,
    visibility_reload_rx: Option<tokio::sync::broadcast::Receiver<()>>,
    channel_tree_shadow: ChannelTreeShadow,
    channel_shadow: SessionChannelShadow,
    user_visibility: UserVisibilityState,
    peer: Option<WebRtcPeer>,
    peer_signal_rx: Option<tokio::sync::mpsc::Receiver<PeerSignal>>,
}

impl Default for SignalingSession {
    fn default() -> Self {
        Self {
            authenticated: false,
            session_id: DEFAULT_WEB_SESSION_ID,
            gateway_config_sent: false,
            client: None,
            outbound_rx: None,
            client_log_rx: None,
            channel_log_rx: None,
            visibility_reload_rx: None,
            channel_tree_shadow: ChannelTreeShadow::new(),
            channel_shadow: SessionChannelShadow::new(),
            user_visibility: UserVisibilityState::default(),
            peer: None,
            peer_signal_rx: None,
        }
    }
}

async fn run_signaling_websocket<S>(
    mut stream: S,
    initial_bytes: Vec<u8>,
    context: SignalingContext,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = WebSocketRead::new(initial_bytes);
    let mut session = SignalingSession::default();
    send_gateway_config(&mut stream, &context, &mut session).await?;
    loop {
        drain_web_visibility_reloads(&mut stream, &context, &mut session, false).await?;
        let disconnected_client = session.client.clone();
        let has_client = disconnected_client.is_some();
        tokio::select! {
            biased;

            _ = async move {
                if let Some(client) = disconnected_client {
                    client.disconnected().await;
                }
            }, if has_client => {
                if let Some(peer) = session.peer.as_ref() {
                    peer.close().await;
                }
                write_websocket_frame(&mut stream, WebSocketOpcode::Close, &[]).await?;
                stream.shutdown().await?;
                return Ok(());
            }

            visibility_reload = async {
                match session.visibility_reload_rx.as_mut() {
                    Some(rx) => Some(rx.recv().await),
                    None => std::future::pending::<Option<
                        Result<(), tokio::sync::broadcast::error::RecvError>,
                    >>().await,
                }
            }, if session.visibility_reload_rx.is_some() => {
                match visibility_reload {
                    Some(Ok(())) | Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                        drain_web_visibility_reloads(&mut stream, &context, &mut session, true).await?;
                    }
                    Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) | None => {
                        session.visibility_reload_rx = None;
                    }
                }
            }
            frame = reader.read_frame(&mut stream) => {
                match frame? {
                    WebSocketFrame::Text(payload) => {
                        handle_signaling_text_frame(&mut stream, &context, &mut session, payload).await?;
                    }
                    WebSocketFrame::Binary(_) => {
                        send_websocket_error(&mut stream, "binary signaling frames are not supported")
                            .await?;
                    }
                    WebSocketFrame::Ping(payload) => {
                        write_websocket_frame(&mut stream, WebSocketOpcode::Pong, &payload).await?;
                    }
                    WebSocketFrame::Pong(_) => {}
                    WebSocketFrame::Close => {
                        if let Some(peer) = session.peer.as_ref() {
                            peer.close().await;
                        }
                        if let Some(server) = context.server.as_ref() {
                            if let Some(client) = session.client.as_ref() {
                                let server_id = client.server_id();
                                let old_channel_id = client.get_current_channel_id();
                                server
                                    .get_clients()
                                    .remove_client_instance_in_server(
                                        &server_id,
                                        client.get_session_id(),
                                        client.client_instance_id(),
                                    )
                                    .await;
                                shitspeak_runtime::client::handlers::temp_channel::reap_if_empty_temporary_on_server(
                                    server,
                                    &server_id,
                                    old_channel_id,
                                )
                                .await;
                            }
                        }
                        write_websocket_frame(&mut stream, WebSocketOpcode::Close, &[]).await?;
                        stream.shutdown().await?;
                        return Ok(());
                    }
                }
            }
            peer_signal = async {
                match session.peer_signal_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending::<Option<PeerSignal>>().await,
                }
            }, if session.peer_signal_rx.is_some() => {
                match peer_signal {
                    Some(signal) => {
                        send_peer_signal(&mut stream, session.peer.as_ref(), signal).await?
                    }
                    None => {
                        send_websocket_error(&mut stream, "web peer signaling queue closed").await?;
                    }
                }
            }
            outbound = async {
                match session.outbound_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending::<Option<Message>>().await,
                }
            }, if session.outbound_rx.is_some() => {
                match outbound {
                    Some(message) => send_web_outbound_message(&mut stream, session.peer.as_ref(), message).await?,
                    None => {
                        send_websocket_error(&mut stream, "web client outbound queue closed").await?;
                    }
                }
            }
            channel_update = async {
                match session.channel_log_rx.as_mut() {
                    Some(rx) => Some(rx.recv().await),
                    None => std::future::pending::<Option<
                        Result<
                            Arc<shitspeak_state::ChannelOperation>,
                            tokio::sync::broadcast::error::RecvError,
                        >,
                    >>().await,
                }
            }, if session.channel_log_rx.is_some() => {
                match channel_update {
                    Some(Ok(op)) => {
                        drain_web_visibility_reloads(&mut stream, &context, &mut session, false).await?;
                        send_web_channel_log_update(&mut stream, &context, &mut session, op).await?;
                    }
                    Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                        drain_web_visibility_reloads(&mut stream, &context, &mut session, false).await?;
                        send_web_channel_snapshot_recovery(&mut stream, &context, &mut session).await?;
                    }
                    Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) | None => {
                        send_websocket_error(&mut stream, "web channel update stream closed").await?;
                    }
                }
            }
            client_update = async {
                match session.client_log_rx.as_mut() {
                    Some(rx) => Some(rx.recv().await),
                    None => std::future::pending::<Option<
                        Result<
                            Arc<shitspeak_runtime::client::state_log::ClientStateBroadcastPayload>,
                            tokio::sync::broadcast::error::RecvError,
                        >,
                    >>().await,
                }
            }, if session.client_log_rx.is_some() => {
                match client_update {
                    Some(Ok(payload)) => {
                        drain_web_visibility_reloads(&mut stream, &context, &mut session, false).await?;
                        send_web_client_log_update(&mut stream, &context, &mut session, payload).await?;
                    }
                    Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                        drain_web_visibility_reloads(&mut stream, &context, &mut session, false).await?;
                        send_web_client_log_gap(&mut stream, &context, &mut session).await?;
                    }
                    Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) | None => {
                        send_websocket_error(&mut stream, "web client update stream closed").await?;
                    }
                }
            }
        }
    }
}

async fn drain_web_visibility_reloads(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
    mut reload_requested: bool,
) -> io::Result<()> {
    reload_requested |= drain_visibility_reload_receiver(&mut session.visibility_reload_rx);
    if !reload_requested {
        return Ok(());
    }

    let (Some(server), Some(client)) = (context.server.as_ref(), session.client.as_ref()) else {
        return Ok(());
    };
    let messages = shitspeak_runtime::client::visibility::visibility_config_reload_messages(
        server,
        client,
        &mut session.user_visibility,
        &mut session.channel_tree_shadow,
        &mut session.channel_shadow,
    )
    .await;
    for message in messages {
        send_web_outbound_message(stream, session.peer.as_ref(), message).await?;
    }
    Ok(())
}

fn drain_visibility_reload_receiver(
    receiver: &mut Option<tokio::sync::broadcast::Receiver<()>>,
) -> bool {
    let mut reload_requested = false;
    let mut receiver_closed = false;
    if let Some(rx) = receiver.as_mut() {
        loop {
            match rx.try_recv() {
                Ok(()) | Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                    reload_requested = true;
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    receiver_closed = true;
                    break;
                }
            }
        }
    }
    if receiver_closed {
        *receiver = None;
    }
    reload_requested
}

async fn send_web_outbound_message(
    stream: &mut (impl AsyncWrite + Unpin),
    peer: Option<&WebRtcPeer>,
    message: Message,
) -> io::Result<()> {
    if let Some(event) = server_event_from_message(message) {
        if let Some(peer) = peer {
            if peer.send_event(&event).await {
                return Ok(());
            }
        }
        send_server_event(stream, &event).await
    } else {
        Ok(())
    }
}

async fn send_peer_signal(
    stream: &mut (impl AsyncWrite + Unpin),
    peer: Option<&WebRtcPeer>,
    signal: PeerSignal,
) -> io::Result<()> {
    match signal {
        PeerSignal::ServerEvent(event) => {
            if let Some(peer) = peer {
                if peer.send_event(&event).await {
                    return Ok(());
                }
            }
            send_server_event(stream, &event).await
        }
        PeerSignal::Answer { sdp } => {
            let payload = serde_json::json!({
                "type": "answer",
                "sdp": sdp,
            });
            write_websocket_frame(
                stream,
                WebSocketOpcode::Text,
                payload.to_string().as_bytes(),
            )
            .await
        }
        PeerSignal::IceCandidate { candidate } => {
            let payload = serde_json::json!({
                "type": "ice_candidate",
                "candidate": candidate,
            });
            write_websocket_frame(
                stream,
                WebSocketOpcode::Text,
                payload.to_string().as_bytes(),
            )
            .await
        }
    }
}

fn server_event_from_message(message: Message) -> Option<ServerEvent> {
    match message {
        Message::UserState(user_state) => Some(ServerEvent::UserState(web_user_state(user_state))),
        Message::UserRemove(remove) => Some(ServerEvent::UserRemove(WebUserRemove {
            session: remove.session,
            actor: remove.actor,
            reason: remove.reason,
            ban: remove.ban,
        })),
        Message::ChannelState(channel_state) => {
            Some(ServerEvent::ChannelState(web_channel_state(channel_state)))
        }
        Message::ChannelRemove(remove) => Some(ServerEvent::ChannelRemove {
            channel_id: remove.channel_id,
        }),
        Message::ServerSync(sync) => Some(ServerEvent::ServerSync(web_server_sync(sync))),
        Message::ServerConfig(config) => Some(ServerEvent::ServerConfig(web_server_config(config))),
        Message::PermissionDenied(denied) => {
            Some(ServerEvent::PermissionDenied(web_permission_denied(denied)))
        }
        Message::CodecVersion(codec) => Some(ServerEvent::CodecVersion(WebCodecVersion {
            alpha: codec.alpha,
            beta: codec.beta,
            prefer_alpha: codec.prefer_alpha,
            opus: codec.opus,
        })),
        Message::TextMessage(text) => Some(ServerEvent::TextMessage {
            sender_session: text.actor.unwrap_or_default(),
            target_sessions: text.session,
            channel_ids: text.channel_id,
            tree_ids: text.tree_id,
            text: text.message,
        }),
        _ => None,
    }
}

fn web_user_state(user_state: shitspeak_proto::mumble_proto::UserState) -> WebUserState {
    let user_id_cleared = user_state.user_id == Some(u32::MAX);
    WebUserState {
        session: user_state.session,
        actor: user_state.actor,
        name: user_state.name,
        user_id: user_state.user_id.filter(|user_id| *user_id != u32::MAX),
        user_id_cleared,
        channel_id: user_state.channel_id,
        mute: user_state.mute,
        deaf: user_state.deaf,
        suppress: user_state.suppress,
        self_mute: user_state.self_mute,
        self_deaf: user_state.self_deaf,
        texture: user_state.texture.map(base64_payload),
        plugin_context: user_state.plugin_context.map(base64_payload),
        plugin_identity: user_state.plugin_identity,
        comment: user_state.comment,
        hash: user_state.hash,
        comment_hash: user_state.comment_hash.map(base64_payload),
        texture_hash: user_state.texture_hash.map(base64_payload),
        priority_speaker: user_state.priority_speaker,
        recording: user_state.recording,
        listening_channel_add: user_state.listening_channel_add,
        listening_channel_remove: user_state.listening_channel_remove,
        listening_volume_adjustment: user_state
            .listening_volume_adjustment
            .into_iter()
            .filter_map(|adjustment| {
                Some(WebVolumeAdjustment {
                    listening_channel: adjustment.listening_channel?,
                    volume_adjustment: adjustment.volume_adjustment?,
                })
            })
            .collect(),
    }
}

fn web_channel_state(
    channel_state: shitspeak_proto::mumble_proto::ChannelState,
) -> WebChannelState {
    WebChannelState {
        channel_id: channel_state.channel_id,
        parent: channel_state.parent,
        name: channel_state.name,
        links: channel_state.links,
        description: channel_state.description,
        links_add: channel_state.links_add,
        links_remove: channel_state.links_remove,
        temporary: channel_state.temporary,
        position: channel_state.position,
        description_hash: channel_state.description_hash.map(base64_payload),
        max_users: channel_state.max_users,
        is_enter_restricted: channel_state.is_enter_restricted,
        can_enter: channel_state.can_enter,
    }
}

fn web_server_sync(sync: shitspeak_proto::mumble_proto::ServerSync) -> WebServerSync {
    WebServerSync {
        session: sync.session,
        max_bandwidth: sync.max_bandwidth,
        welcome_text: sync.welcome_text,
        permissions: sync.permissions.map(|permissions| permissions as u32),
    }
}

fn web_server_config(config: shitspeak_proto::mumble_proto::ServerConfig) -> WebServerConfig {
    WebServerConfig {
        max_bandwidth: config.max_bandwidth,
        welcome_text: config.welcome_text,
        allow_html: config.allow_html,
        message_length: config.message_length,
        image_message_length: config.image_message_length,
        max_users: config.max_users,
        recording_allowed: config.recording_allowed,
    }
}

fn web_permission_denied(
    denied: shitspeak_proto::mumble_proto::PermissionDenied,
) -> WebPermissionDenied {
    WebPermissionDenied {
        deny_type: denied.r#type.and_then(web_deny_type_name),
        session: denied.session,
        channel_id: denied.channel_id,
        reason: denied.reason,
        name: denied.name,
        permission: denied.permission,
    }
}

fn base64_payload(payload: Vec<u8>) -> String {
    base64::engine::general_purpose::STANDARD.encode(payload)
}

fn web_deny_type_name(value: i32) -> Option<String> {
    use shitspeak_proto::mumble_proto::permission_denied::DenyType;

    let deny_type = match value {
        0 => DenyType::Text,
        1 => DenyType::Permission,
        2 => DenyType::SuperUser,
        3 => DenyType::ChannelName,
        4 => DenyType::TextTooLong,
        5 => DenyType::H9k,
        6 => DenyType::TemporaryChannel,
        7 => DenyType::MissingCertificate,
        8 => DenyType::UserName,
        9 => DenyType::ChannelFull,
        10 => DenyType::NestingLimit,
        11 => DenyType::ChannelCountLimit,
        12 => DenyType::ChannelListenerLimit,
        13 => DenyType::UserListenerLimit,
        _ => return None,
    };
    Some(deny_type.as_str_name().to_string())
}

async fn handle_signaling_text_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
    payload: String,
) -> io::Result<()> {
    match serde_json::from_str::<SignalingRequest>(&payload) {
        Ok(SignalingRequest::Offer { sdp, speaker_slots }) => {
            if context.requires_authentication() && !session.authenticated {
                send_websocket_error(stream, "authentication required before webrtc offer").await?;
                return Ok(());
            }
            handle_signaling_offer(stream, context, session, sdp, speaker_slots).await
        }
        Ok(SignalingRequest::IceCandidate { candidate }) => {
            if context.requires_authentication() && !session.authenticated {
                send_websocket_error(stream, "authentication required before ice candidate")
                    .await?;
                return Ok(());
            }
            handle_signaling_ice_candidate(stream, session, candidate).await
        }
        Ok(SignalingRequest::Authenticate { auth }) => {
            handle_signaling_authenticate(stream, context, session, auth).await
        }
        Ok(SignalingRequest::JoinChannel { channel_id }) => {
            handle_signaling_client_command(
                stream,
                context,
                session,
                ClientCommand::JoinChannel { channel_id },
            )
            .await
        }
        Ok(SignalingRequest::SendText { text }) => {
            handle_signaling_client_command(
                stream,
                context,
                session,
                ClientCommand::SendText { text },
            )
            .await
        }
        Ok(SignalingRequest::SetMute { muted }) => {
            handle_signaling_client_command(
                stream,
                context,
                session,
                ClientCommand::SetMute { muted },
            )
            .await
        }
        Ok(SignalingRequest::SetDeaf { deafened }) => {
            handle_signaling_client_command(
                stream,
                context,
                session,
                ClientCommand::SetDeaf { deafened },
            )
            .await
        }
        Ok(SignalingRequest::VoiceControl { ptt, target, epoch }) => {
            handle_signaling_client_command(
                stream,
                context,
                session,
                ClientCommand::VoiceControl {
                    ptt,
                    target: target.unwrap_or(crate::protocol::VoiceTarget::Normal),
                    epoch,
                },
            )
            .await
        }
        Err(_) => send_websocket_error(stream, "invalid signaling message").await,
    }
}

async fn handle_signaling_offer(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
    sdp: String,
    speaker_slots: Option<u32>,
) -> io::Result<()> {
    if session.peer.is_none() {
        let (signal_tx, signal_rx) = tokio::sync::mpsc::channel(256);
        let mut peer_config = context.config.webrtc.clone();
        peer_config.max_speaker_ssrcs =
            negotiated_speaker_slots(speaker_slots, context.config.webrtc.max_speaker_ssrcs);
        let peer = WebRtcPeer::new(
            peer_config,
            context.server.clone(),
            session.client.clone(),
            signal_tx,
        )
        .await
        .map_err(|error| io::Error::other(format!("create web peer: {error}")))?;
        session.peer = Some(peer);
        session.peer_signal_rx = Some(signal_rx);
    }

    let Some(peer) = session.peer.as_ref() else {
        send_websocket_error(stream, "web peer connection is not available").await?;
        return Ok(());
    };
    match peer.answer_offer(sdp).await {
        Ok(answer_sdp) => {
            send_peer_signal(
                stream,
                session.peer.as_ref(),
                PeerSignal::Answer { sdp: answer_sdp },
            )
            .await
        }
        Err(error) => {
            tracing::warn!(error = %error, "failed to answer web rtc offer");
            send_websocket_error(stream, &format!("failed to answer webrtc offer: {error}")).await
        }
    }
}

fn negotiated_speaker_slots(requested: Option<u32>, server_max: u32) -> u32 {
    requested.unwrap_or(server_max).clamp(1, server_max.max(1))
}

async fn send_gateway_config(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
) -> io::Result<()> {
    if session.gateway_config_sent {
        return Ok(());
    }
    session.gateway_config_sent = true;
    send_server_event(
        stream,
        &ServerEvent::GatewayConfig(WebGatewayConfig {
            max_speaker_slots: context.config.webrtc.max_speaker_ssrcs.max(1),
            audio_bitrate: context.config.webrtc.audio_bitrate,
            transports: gateway_transports(&context.config),
            moq: gateway_moq_config(&context.config),
        }),
    )
    .await
}

fn gateway_transports(config: &WebConfig) -> Vec<WebTransportKind> {
    let mut transports = vec![WebTransportKind::WebRtc];
    if moq_gateway_available(config) {
        transports.push(WebTransportKind::Moq);
    }
    transports
}

fn gateway_moq_config(config: &WebConfig) -> Option<WebMoqGatewayConfig> {
    moq_gateway_available(config).then(|| WebMoqGatewayConfig {
        url: config.moq.public_url.clone(),
        max_speaker_tracks: config.moq.max_speaker_tracks.max(1),
        audio_bitrate: config.moq.audio_bitrate,
    })
}

fn moq_gateway_available(config: &WebConfig) -> bool {
    config.moq.enabled && config.moq.listen.is_some()
}

#[cfg(test)]
mod gateway_config_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn config_with_moq(enabled: bool, listen: Option<SocketAddr>) -> WebConfig {
        WebConfig {
            enabled: true,
            moq: shitspeak_runtime_config::WebMoqConfig {
                enabled,
                listen,
                public_url: Some("https://voice.example.test/web/moq".to_string()),
                cert_path: None,
                key_path: None,
                max_speaker_tracks: 6,
                audio_bitrate: 32_000,
            },
            ..Default::default()
        }
    }

    #[test]
    fn gateway_config_advertises_moq_only_when_listener_exists() {
        let config = config_with_moq(
            true,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64740)),
        );
        assert_eq!(
            gateway_transports(&config),
            vec![WebTransportKind::WebRtc, WebTransportKind::Moq]
        );
        assert_eq!(
            gateway_moq_config(&config),
            Some(WebMoqGatewayConfig {
                url: Some("https://voice.example.test/web/moq".to_string()),
                max_speaker_tracks: 6,
                audio_bitrate: 32_000,
            })
        );

        let missing_listener = config_with_moq(true, None);
        assert_eq!(
            gateway_transports(&missing_listener),
            vec![WebTransportKind::WebRtc]
        );
        assert_eq!(gateway_moq_config(&missing_listener), None);
    }
}

async fn handle_signaling_ice_candidate(
    stream: &mut (impl AsyncWrite + Unpin),
    session: &mut SignalingSession,
    candidate: serde_json::Value,
) -> io::Result<()> {
    let Some(peer) = session.peer.as_ref() else {
        send_websocket_error(stream, "webrtc offer required before ice candidate").await?;
        return Ok(());
    };
    match peer.add_ice_candidate(candidate).await {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::trace!(error = %error, "failed to add web rtc ice candidate");
            send_websocket_error(stream, &format!("failed to add ice candidate: {error}")).await
        }
    }
}

async fn handle_signaling_authenticate(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
    auth: AuthRequest,
) -> io::Result<()> {
    if session.authenticated {
        send_server_event(
            stream,
            &ServerEvent::AuthenticationRejected {
                reason: "already authenticated".to_string(),
            },
        )
        .await?;
        return Ok(());
    }

    let Some(authenticator) = context.authenticator.as_ref() else {
        send_server_event(
            stream,
            &ServerEvent::AuthenticationRejected {
                reason: "web authentication is not wired to this server".to_string(),
            },
        )
        .await?;
        return Ok(());
    };

    match auth {
        AuthRequest::Password { username, password } => {
            if !context.config.auth.password_enabled
                || !context.config.auth.modes.contains(&WebAuthMode::Password)
            {
                send_server_event(
                    stream,
                    &ServerEvent::AuthenticationRejected {
                        reason: "password authentication is disabled".to_string(),
                    },
                )
                .await?;
                return Ok(());
            }

            let preallocated = if let Some(server) = context.server.as_ref() {
                let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel::<Message>(256);
                let client = server
                    .get_clients()
                    .allocate_web_client_in_server(
                        context.provisional_server_id.clone(),
                        context.real_ip,
                        context.peer_addr,
                        context.local_addr,
                        outbound_tx,
                    )
                    .await;
                session.session_id = u32::from(client.get_session_id());
                Some((Arc::clone(server), client, outbound_rx))
            } else {
                None
            };
            let auth_session_id = preallocated
                .as_ref()
                .map(|(_, client, _)| u32::from(client.get_session_id()))
                .unwrap_or(session.session_id);
            let auxiliary = context.auxiliary_data(auth_session_id);
            match authenticator
                .authenticate(&username, Some(password.as_str()), &auxiliary)
                .await
            {
                Ok(result) if result.user_id != Some(u32::MAX) => {
                    handle_successful_password_auth(
                        stream,
                        context,
                        session,
                        preallocated,
                        result,
                        Some(Credential::new(username, Some(password))),
                    )
                    .await
                }
                Ok(_) => {
                    if let Some((server, client, _)) = preallocated {
                        let server_id = client.server_id();
                        server
                            .get_clients()
                            .remove_client_instance_in_server(
                                &server_id,
                                client.get_session_id(),
                                client.client_instance_id(),
                            )
                            .await;
                        session.session_id = DEFAULT_WEB_SESSION_ID;
                    }
                    send_authentication_rejection(stream, AuthenticationRejection::RetryLater).await
                }
                Err(rejection) => {
                    if let Some((server, client, _)) = preallocated {
                        let server_id = client.server_id();
                        server
                            .get_clients()
                            .remove_client_instance_in_server(
                                &server_id,
                                client.get_session_id(),
                                client.client_instance_id(),
                            )
                            .await;
                        session.session_id = DEFAULT_WEB_SESSION_ID;
                    }
                    send_authentication_rejection(stream, rejection).await
                }
            }
        }
        AuthRequest::Sso { token } => {
            let _ = token;
            send_server_event(
                stream,
                &ServerEvent::AuthenticationRejected {
                    reason: "sso authentication is not implemented yet".to_string(),
                },
            )
            .await
        }
    }
}

async fn handle_signaling_client_command(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
    command: ClientCommand,
) -> io::Result<()> {
    if context.requires_authentication() && !session.authenticated {
        send_websocket_error(stream, "authentication required before control command").await?;
        return Ok(());
    }

    let (Some(server), Some(client)) = (context.server.as_ref(), session.client.as_ref()) else {
        send_websocket_error(stream, "web control command is not wired to this server").await?;
        return Ok(());
    };

    if !client_is_current(server, client).await {
        send_websocket_error(stream, "web client is no longer connected").await?;
        return Ok(());
    }

    if let ClientCommand::VoiceControl { ptt, target, epoch } = command {
        let Some(peer) = session.peer.as_ref() else {
            send_websocket_error(stream, "webrtc offer required before voice control").await?;
            return Ok(());
        };
        let event = peer.apply_voice_control(ptt, target, epoch).await;
        if !peer.send_event(&event).await {
            send_server_event(stream, &event).await?;
        }
        return Ok(());
    }

    let Some(message) = control_message_from_command(client, command) else {
        return Ok(());
    };
    let result = tokio::select! {
        biased;
        _ = client.disconnected() => {
            send_websocket_error(stream, "web client is no longer connected").await?;
            return Ok(());
        }
        result = client.handle_message(server, message) => result,
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            client.in_tracing_scope(|| {
                tracing::warn!(
                    session = session.session_id,
                    error = %error,
                    "web control command failed"
                );
            });
            send_websocket_error(stream, &format!("control command failed: {error}")).await
        }
    }
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

async fn handle_successful_password_auth(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
    preallocated: Option<(
        Arc<Box<Server>>,
        Arc<Box<Client>>,
        tokio::sync::mpsc::Receiver<Message>,
    )>,
    result: AuthenticateResult,
    credential: Option<Credential>,
) -> io::Result<()> {
    let display_name = result.display_name.clone();
    let mut initial_state_client = None;
    if let Some((server, client, outbound_rx)) = preallocated {
        session.outbound_rx = Some(outbound_rx);
        if let Err(error) =
            crate::session::configure_authenticated_client(&server, &client, result, credential)
                .await
        {
            let server_id = client.server_id();
            server
                .get_clients()
                .remove_client_instance_in_server(
                    &server_id,
                    client.get_session_id(),
                    client.client_instance_id(),
                )
                .await;
            session.outbound_rx = None;
            session.session_id = DEFAULT_WEB_SESSION_ID;
            return send_server_event(
                stream,
                &ServerEvent::AuthenticationRejected {
                    reason: error.reason().to_string(),
                },
            )
            .await;
        }
        session.session_id = u32::from(client.get_session_id());
        initial_state_client = Some((Arc::clone(&server), Arc::clone(&client)));
        session.client = Some(client);
    } else if let Some(server) = context.server.as_ref() {
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel::<Message>(256);
        let client = server
            .get_clients()
            .allocate_web_client_in_server(
                context.provisional_server_id.clone(),
                context.real_ip,
                context.peer_addr,
                context.local_addr,
                outbound_tx,
            )
            .await;
        session.outbound_rx = Some(outbound_rx);
        if let Err(error) =
            crate::session::configure_authenticated_client(server, &client, result, credential)
                .await
        {
            let server_id = client.server_id();
            server
                .get_clients()
                .remove_client_instance_in_server(
                    &server_id,
                    client.get_session_id(),
                    client.client_instance_id(),
                )
                .await;
            session.outbound_rx = None;
            session.session_id = DEFAULT_WEB_SESSION_ID;
            return send_server_event(
                stream,
                &ServerEvent::AuthenticationRejected {
                    reason: error.reason().to_string(),
                },
            )
            .await;
        }
        session.session_id = u32::from(client.get_session_id());
        initial_state_client = Some((Arc::clone(server), Arc::clone(&client)));
        session.client = Some(client);
    }

    send_authentication_success(stream, session.session_id, display_name).await?;
    session.authenticated = true;
    if let Some((server, client)) = initial_state_client {
        session.visibility_reload_rx = Some(server.subscribe_visibility_reload());
        let (_clients, client_versions, client_epochs, client_log_rx) = server
            .get_clients()
            .published_snapshot_with_versions_and_subscription_in_server(&client.server_id())
            .await;
        let (channel_snapshot, channel_version, channel_log_rx) = server
            .get_channels()
            .ordered_snapshot_with_version_and_subscription_in_server(&client.server_id())
            .await;
        send_initial_server_state(
            stream,
            &server,
            &client,
            &channel_snapshot,
            &mut session.channel_tree_shadow,
            &mut session.channel_shadow,
            &mut session.user_visibility,
        )
        .await?;
        client.set_last_channel_version(channel_version).await;
        client
            .set_last_client_cursors(client_versions, client_epochs)
            .await;
        session.client_log_rx = Some(client_log_rx);
        session.channel_log_rx = Some(channel_log_rx);
        shitspeak_runtime::client::handlers::spawn_staged_session_blob_resolution(
            Arc::clone(&server),
            Arc::clone(&client),
        );
    }
    Ok(())
}

async fn send_initial_server_state(
    stream: &mut (impl AsyncWrite + Unpin),
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channels: &shitspeak_state::OrderedChannelSnapshot,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> io::Result<()> {
    let server_id = client.server_id();
    for message in
        shitspeak_runtime::channel_handler::build_visible_ordered_channel_snapshot_messages(
            server,
            client,
            channels,
            channel_tree_shadow,
            server.get_send_permission_info(),
        )
        .await
    {
        send_web_outbound_message(stream, None, message).await?;
    }

    let session_id = client.get_session_id();
    for visible in server
        .get_clients()
        .get_all_clients_in_server(&server_id)
        .await
    {
        if !visible.is_authenticated() || !visible.is_published() {
            continue;
        }
        if visible.get_session_id() == session_id {
            continue;
        }
        let user_state: Message = visible.build_user_state_for_broadcast().into();
        for message in shitspeak_runtime::channel_handler::project_message_with_visibility_shadows(
            server,
            client,
            channel_tree_shadow,
            user_visibility,
            channel_shadow,
            &server_id,
            &user_state,
        )
        .await
        {
            send_web_outbound_message(stream, None, message).await?;
        }
    }

    let self_state: Message = client.build_user_state_for_broadcast().into();
    for message in shitspeak_runtime::channel_handler::project_message_with_visibility_shadows(
        server,
        client,
        channel_tree_shadow,
        user_visibility,
        channel_shadow,
        &server_id,
        &self_state,
    )
    .await
    {
        send_web_outbound_message(stream, None, message).await?;
    }

    let root_permissions =
        shitspeak_runtime::client::acl::compute_permissions_for_client(server, client, 0).await;
    send_web_outbound_message(
        stream,
        None,
        ServerSync {
            session: Some(u32::from(session_id)),
            max_bandwidth: Some(client.max_bandwidth(server.get_max_bandwidth())),
            welcome_text: server.get_welcome_text(),
            permissions: Some(root_permissions),
        }
        .into(),
    )
    .await?;

    send_web_outbound_message(
        stream,
        None,
        ServerConfig {
            max_bandwidth: None,
            welcome_text: None,
            allow_html: Some(server.get_allow_html()),
            message_length: Some(server.get_max_text_message_length()),
            image_message_length: Some(server.get_max_image_message_length()),
            max_users: Some(server.get_max_users() as u32),
        }
        .into(),
    )
    .await?;

    send_web_outbound_message(
        stream,
        None,
        CodecVersion {
            alpha: -2147483637,
            beta: 0,
            prefer_alpha: false,
            opus: Some(true),
        }
        .into(),
    )
    .await
}

async fn send_web_channel_log_update(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
    op: Arc<shitspeak_state::ChannelOperation>,
) -> io::Result<()> {
    let Some(server) = context.server.as_ref().cloned() else {
        return Ok(());
    };
    let Some(client) = session.client.as_ref().cloned() else {
        return Ok(());
    };

    let last = client.get_last_channel_version().await;
    let server_id = client.server_id();
    if op.server_id != server_id {
        return Ok(());
    }
    if op.is_root_name_config_update() {
        send_web_channel_snapshot_recovery(stream, context, session).await?;
        return Ok(());
    }
    if op.version <= last {
        return Ok(());
    }
    if op.version > last + 1 {
        send_web_channel_log_gap(stream, context, session).await?;
        let last = client.get_last_channel_version().await;
        if op.version <= last {
            return Ok(());
        }
    }

    let acl_context = shitspeak_runtime::channel_handler::ClientAclOperationContext::for_operation_with_permission_queries(
        &server,
        &client,
        server.get_channels(),
        &op,
        false,
    )
    .await;
    let refresh_scope = shitspeak_runtime::client::visibility::visibility_refresh_scope_for_channel_operation_with_state_for_client(
        &server,
        &client,
        &op,
        &mut session.user_visibility,
    )
    .await;
    let channel_refresh =
        shitspeak_runtime::channel_handler::prepare_channel_visibility_refresh_with_acl_context(
            &server,
            &client,
            &session.channel_tree_shadow,
            &refresh_scope,
            acl_context.as_ref(),
        )
        .await;
    let messages =
        shitspeak_runtime::channel_handler::convert_channel_operation_to_messages_with_acl_context_options(
            &server,
            &client,
            &op,
            server.get_channels(),
            Some(&mut session.channel_shadow),
            acl_context.as_ref(),
            false,
        )
        .await;
    let mut deferred_channel_removals = Vec::new();
    for message in messages {
        if matches!(message, Message::ChannelRemove(_)) {
            deferred_channel_removals.extend(
                shitspeak_runtime::channel_handler::project_channel_message(
                    &server,
                    &client,
                    &session.channel_tree_shadow,
                    &message,
                )
                .await,
            );
            continue;
        }
        send_web_outbound_message_with_synthetic(
            stream,
            &server,
            &client,
            session.peer.as_ref(),
            &mut session.channel_tree_shadow,
            &mut session.channel_shadow,
            &mut session.user_visibility,
            &server_id,
            &message,
        )
        .await?;
    }
    send_prepared_web_visibility_refresh(
        stream,
        &server,
        &client,
        session.peer.as_ref(),
        &mut session.channel_tree_shadow,
        &mut session.channel_shadow,
        &mut session.user_visibility,
        &server_id,
        channel_refresh,
        refresh_scope,
        acl_context.as_ref(),
    )
    .await?;
    for message in deferred_channel_removals {
        if let Message::ChannelRemove(channel_remove) = &message {
            if !session
                .channel_tree_shadow
                .contains(&channel_remove.channel_id)
            {
                continue;
            }
        }
        session.channel_tree_shadow.sync_message(&message);
        send_web_outbound_message(stream, session.peer.as_ref(), message).await?;
    }
    shitspeak_runtime::channel_handler::remove_deleted_channels_from_shadow(
        server.get_channels(),
        &op,
        &mut session.channel_tree_shadow,
    );
    client.set_last_channel_version(op.version).await;
    Ok(())
}

async fn send_web_channel_log_gap(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
) -> io::Result<()> {
    let Some(server) = context.server.as_ref().cloned() else {
        return Ok(());
    };
    let Some(client) = session.client.as_ref().cloned() else {
        return Ok(());
    };

    let last = client.get_last_channel_version().await;
    let server_id = client.server_id();
    let missed = server
        .get_channels()
        .get_log_since_in_server(&server_id, last)
        .await;
    if missed.is_empty()
        || missed
            .first()
            .is_some_and(|op| op.version > last.saturating_add(1))
    {
        return send_web_channel_snapshot_recovery(stream, context, session).await;
    }

    for op in missed {
        let acl_context =
            shitspeak_runtime::channel_handler::ClientAclOperationContext::for_operation_with_permission_queries(
                &server,
                &client,
                server.get_channels(),
                &op,
                false,
            )
            .await;
        let refresh_scope = shitspeak_runtime::client::visibility::visibility_refresh_scope_for_channel_operation_with_state_for_client(
            &server,
            &client,
            &op,
            &mut session.user_visibility,
        )
        .await;
        let channel_refresh = shitspeak_runtime::channel_handler::prepare_channel_visibility_refresh_with_acl_context(
            &server,
            &client,
            &session.channel_tree_shadow,
            &refresh_scope,
            acl_context.as_ref(),
        )
        .await;
        let messages = shitspeak_runtime::channel_handler::convert_channel_operation_to_messages_with_acl_context_options(
            &server,
            &client,
            &op,
            server.get_channels(),
            Some(&mut session.channel_shadow),
            acl_context.as_ref(),
            false,
        )
        .await;
        let mut deferred_channel_removals = Vec::new();
        for message in messages {
            if matches!(message, Message::ChannelRemove(_)) {
                deferred_channel_removals.extend(
                    shitspeak_runtime::channel_handler::project_channel_message(
                        &server,
                        &client,
                        &session.channel_tree_shadow,
                        &message,
                    )
                    .await,
                );
                continue;
            }
            send_web_outbound_message_with_synthetic(
                stream,
                &server,
                &client,
                session.peer.as_ref(),
                &mut session.channel_tree_shadow,
                &mut session.channel_shadow,
                &mut session.user_visibility,
                &server_id,
                &message,
            )
            .await?;
        }
        send_prepared_web_visibility_refresh(
            stream,
            &server,
            &client,
            session.peer.as_ref(),
            &mut session.channel_tree_shadow,
            &mut session.channel_shadow,
            &mut session.user_visibility,
            &server_id,
            channel_refresh,
            refresh_scope,
            acl_context.as_ref(),
        )
        .await?;
        for message in deferred_channel_removals {
            if let Message::ChannelRemove(channel_remove) = &message {
                if !session
                    .channel_tree_shadow
                    .contains(&channel_remove.channel_id)
                {
                    continue;
                }
            }
            session.channel_tree_shadow.sync_message(&message);
            send_web_outbound_message(stream, session.peer.as_ref(), message).await?;
        }
        shitspeak_runtime::channel_handler::remove_deleted_channels_from_shadow(
            server.get_channels(),
            &op,
            &mut session.channel_tree_shadow,
        );
        client.set_last_channel_version(op.version).await;
    }
    Ok(())
}

async fn send_web_channel_snapshot_recovery(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
) -> io::Result<()> {
    let Some(server) = context.server.as_ref().cloned() else {
        return Ok(());
    };
    let Some(client) = session.client.as_ref().cloned() else {
        return Ok(());
    };
    let server_id = client.server_id();
    let (snapshot, version) = server
        .get_channels()
        .ordered_snapshot_with_version_in_server(&server_id)
        .await;
    let previous = session.channel_tree_shadow.clone();
    let mut current = ChannelTreeShadow::new();
    let messages =
        shitspeak_runtime::channel_handler::build_visible_ordered_channel_snapshot_messages(
            &server,
            &client,
            &snapshot,
            &mut current,
            server.get_send_permission_info(),
        )
        .await;
    session.channel_tree_shadow = current;
    for message in messages {
        send_web_outbound_message(stream, session.peer.as_ref(), message).await?;
    }

    let visibility_messages =
        shitspeak_runtime::client::visibility::visibility_config_reload_messages(
            &server,
            &client,
            &mut session.user_visibility,
            &mut session.channel_tree_shadow,
            &mut session.channel_shadow,
        )
        .await;
    for message in visibility_messages {
        send_web_outbound_message(stream, session.peer.as_ref(), message).await?;
    }

    let mut removed = previous
        .difference(&session.channel_tree_shadow)
        .copied()
        .collect::<Vec<_>>();
    removed.sort_unstable_by(|left, right| right.cmp(left));
    for channel_id in removed {
        send_web_outbound_message(
            stream,
            session.peer.as_ref(),
            ChannelRemove { channel_id }.into(),
        )
        .await?;
    }
    client.set_last_channel_version(version).await;
    Ok(())
}

async fn send_web_client_log_update(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
    payload: Arc<shitspeak_runtime::client::state_log::ClientStateBroadcastPayload>,
) -> io::Result<()> {
    let Some(server) = context.server.as_ref().cloned() else {
        return Ok(());
    };
    let Some(client) = session.client.as_ref().cloned() else {
        return Ok(());
    };

    let entry = &payload.entry;
    let server_id = client.server_id();
    if matches!(entry.op, ClientStateOperation::ResetNode { .. }) {
        match payload.versions.get(&entry.node_id).copied() {
            Some(0) => {
                send_web_client_origin_reset(
                    stream,
                    &server,
                    &client,
                    session.peer.as_ref(),
                    &mut session.channel_tree_shadow,
                    &mut session.channel_shadow,
                    &mut session.user_visibility,
                    &server_id,
                    entry.node_id,
                )
                .await?;
                client.remove_last_client_version(entry.node_id).await;
                return Ok(());
            }
            Some(_) => {
                client.update_last_client_versions(&payload.versions).await;
                return Ok(());
            }
            None => {}
        }
    }
    if entry.op.server_id() != server_id {
        return Ok(());
    }
    let last_seen = client.get_last_client_versions().await;
    let mut last_for_node = last_seen.get(&entry.node_id).copied().unwrap_or(0);
    match payload.versions.get(&entry.node_id).copied() {
        Some(0) => {
            last_for_node = entry.version.saturating_sub(1);
        }
        Some(current) if current < last_for_node => {
            last_for_node = 0;
        }
        _ => {}
    }
    if entry.version <= last_for_node {
        return Ok(());
    }
    if entry.version > last_for_node + 1 {
        send_web_client_log_gap(stream, context, session).await?;
        let last_seen = client.get_last_client_versions().await;
        let last_for_node = last_seen.get(&entry.node_id).copied().unwrap_or(0);
        if entry.version <= last_for_node {
            return Ok(());
        }
    }
    if is_own_add_client(&entry.op, client.get_session_id()) {
        client.update_last_client_versions(&payload.versions).await;
        return Ok(());
    }
    if is_known_add_client(&entry.op, &session.channel_shadow) {
        client.update_last_client_versions(&payload.versions).await;
        return Ok(());
    }

    send_web_client_log_entry(
        stream,
        &server,
        &client,
        session.peer.as_ref(),
        &mut session.channel_tree_shadow,
        &mut session.channel_shadow,
        &mut session.user_visibility,
        entry,
    )
    .await?;
    client.update_last_client_versions(&payload.versions).await;
    Ok(())
}

fn is_own_add_client(op: &ClientStateOperation, session_id: ClientSessionIdentifier) -> bool {
    matches!(op, ClientStateOperation::AddClient { session_id: id, .. } if *id == session_id)
}

fn is_known_add_client(op: &ClientStateOperation, shadow: &SessionChannelShadow) -> bool {
    matches!(
        op,
        ClientStateOperation::AddClient { session_id, .. } if shadow.contains_key(session_id)
    )
}

async fn send_web_client_log_gap(
    stream: &mut (impl AsyncWrite + Unpin),
    context: &SignalingContext,
    session: &mut SignalingSession,
) -> io::Result<()> {
    let Some(server) = context.server.as_ref().cloned() else {
        return Ok(());
    };
    let Some(client) = session.client.as_ref().cloned() else {
        return Ok(());
    };

    let last_seen = client.get_last_client_versions().await;
    let last_epochs = client.get_last_client_epochs().await;
    let server_id = client.server_id();
    let catch_up = server
        .get_clients()
        .replay_entries_since_in_server_for_client(
            &server_id,
            &last_seen,
            &last_epochs,
            client.get_session_id(),
            client.client_instance_id(),
        )
        .await;
    let (rebases, missed, versions, epochs) = catch_up.into_parts();
    for rebase in rebases {
        let (origin, _version, _epoch, entries) = rebase.into_parts();
        send_web_client_origin_reset(
            stream,
            &server,
            &client,
            session.peer.as_ref(),
            &mut session.channel_tree_shadow,
            &mut session.channel_shadow,
            &mut session.user_visibility,
            &server_id,
            origin,
        )
        .await?;
        for entry in entries {
            if is_own_add_client(&entry.op, client.get_session_id())
                || is_known_add_client(&entry.op, &session.channel_shadow)
            {
                continue;
            }
            send_web_client_log_entry(
                stream,
                &server,
                &client,
                session.peer.as_ref(),
                &mut session.channel_tree_shadow,
                &mut session.channel_shadow,
                &mut session.user_visibility,
                &entry,
            )
            .await?;
        }
    }
    for entry in missed {
        if is_own_add_client(&entry.op, client.get_session_id())
            || is_known_add_client(&entry.op, &session.channel_shadow)
        {
            continue;
        }
        send_web_client_log_entry(
            stream,
            &server,
            &client,
            session.peer.as_ref(),
            &mut session.channel_tree_shadow,
            &mut session.channel_shadow,
            &mut session.user_visibility,
            &entry,
        )
        .await?;
    }
    client.set_last_client_cursors(versions, epochs).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_web_client_origin_reset(
    stream: &mut (impl AsyncWrite + Unpin),
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    peer: Option<&WebRtcPeer>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    server_id: &str,
    origin: u16,
) -> io::Result<()> {
    let viewer_session = client.get_session_id();
    let sessions = channel_shadow
        .iter()
        .map(|(session, _)| session)
        .filter(|session| session.get_node_id() == origin)
        .collect::<Vec<_>>();
    for session in &sessions {
        if *session != viewer_session {
            channel_shadow.remove(session);
        }
    }

    for session in sessions {
        if session == viewer_session {
            continue;
        }
        let removal: Message = shitspeak_runtime::messages::encoder::UserRemove {
            session: u32::from(session),
            actor: None,
            reason: None,
            ban: Some(false),
        }
        .into();
        send_web_outbound_message_with_synthetic(
            stream,
            server,
            client,
            peer,
            channel_tree_shadow,
            channel_shadow,
            user_visibility,
            server_id,
            &removal,
        )
        .await?;
    }
    Ok(())
}

async fn send_web_client_log_entry(
    stream: &mut (impl AsyncWrite + Unpin),
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    peer: Option<&WebRtcPeer>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    entry: &ClientStateLogEntry,
) -> io::Result<()> {
    for message in shitspeak_runtime::channel_handler::project_client_log_entry_transition(
        server,
        client,
        channel_tree_shadow,
        user_visibility,
        channel_shadow,
        entry,
    )
    .await
    {
        send_web_outbound_message(stream, peer, message).await?;
    }
    Ok(())
}

async fn send_web_outbound_message_with_synthetic(
    stream: &mut (impl AsyncWrite + Unpin),
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    peer: Option<&WebRtcPeer>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    server_id: &str,
    message: &Message,
) -> io::Result<()> {
    for message in shitspeak_runtime::channel_handler::project_message_with_visibility_shadows(
        server,
        client,
        channel_tree_shadow,
        user_visibility,
        channel_shadow,
        server_id,
        message,
    )
    .await
    {
        send_web_outbound_message(stream, peer, message).await?;
    }
    Ok(())
}

async fn send_prepared_web_visibility_refresh(
    stream: &mut (impl AsyncWrite + Unpin),
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    peer: Option<&WebRtcPeer>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    server_id: &str,
    channel_refresh: shitspeak_runtime::channel_handler::ChannelVisibilityRefresh,
    scope: shitspeak_runtime::client::visibility::VisibilityRefreshScope,
    acl_context: Option<&shitspeak_runtime::channel_handler::ClientAclOperationContext>,
) -> io::Result<()> {
    let mut additions = Vec::new();
    channel_refresh.append_additions_to(&mut additions);
    channel_refresh.apply_additions(channel_tree_shadow);
    for message in additions {
        send_web_outbound_message(stream, peer, message).await?;
    }

    send_prepared_web_visibility_refresh_without_additions(
        stream,
        server,
        client,
        peer,
        channel_tree_shadow,
        channel_shadow,
        user_visibility,
        server_id,
        channel_refresh,
        scope,
        acl_context,
    )
    .await
}

async fn send_prepared_web_visibility_refresh_without_additions(
    stream: &mut (impl AsyncWrite + Unpin),
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    peer: Option<&WebRtcPeer>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    server_id: &str,
    channel_refresh: shitspeak_runtime::channel_handler::ChannelVisibilityRefresh,
    scope: shitspeak_runtime::client::visibility::VisibilityRefreshScope,
    acl_context: Option<&shitspeak_runtime::channel_handler::ClientAclOperationContext>,
) -> io::Result<()> {
    for message in shitspeak_runtime::client::visibility::visibility_refresh_messages_with_shadow_and_acl_context(
        server,
        client,
        user_visibility,
        channel_shadow,
        server_id,
        scope,
        acl_context,
    )
    .await
    {
        send_web_outbound_message(stream, peer, message).await?;
    }

    let mut removals = Vec::new();
    channel_refresh.apply_removals(channel_tree_shadow);
    channel_refresh.append_removals_to(&mut removals);
    for message in removals {
        send_web_outbound_message(stream, peer, message).await?;
    }
    Ok(())
}

async fn send_authentication_success(
    stream: &mut (impl AsyncWrite + Unpin),
    session_id: u32,
    display_name: Option<String>,
) -> io::Result<()> {
    send_server_event(
        stream,
        &ServerEvent::Authenticated {
            session: session_id,
            display_name,
        },
    )
    .await
}

async fn send_authentication_rejection(
    stream: &mut (impl AsyncWrite + Unpin),
    rejection: AuthenticationRejection,
) -> io::Result<()> {
    let reason = match rejection {
        AuthenticationRejection::WrongPassword => "wrong password",
        AuthenticationRejection::NoSuchUser => "no such user",
        AuthenticationRejection::RetryLater => "authenticator temporarily unavailable",
    };
    send_server_event(
        stream,
        &ServerEvent::AuthenticationRejected {
            reason: reason.to_string(),
        },
    )
    .await
}

async fn send_server_event(
    stream: &mut (impl AsyncWrite + Unpin),
    event: &ServerEvent,
) -> io::Result<()> {
    let payload = encode_server_event(event)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_websocket_frame(stream, WebSocketOpcode::Text, payload.as_bytes()).await
}

async fn send_websocket_error(
    stream: &mut (impl AsyncWrite + Unpin),
    message: &str,
) -> io::Result<()> {
    send_server_event(
        stream,
        &ServerEvent::Error {
            message: message.to_string(),
        },
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebSocketOpcode {
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl WebSocketOpcode {
    fn from_byte(byte: u8) -> io::Result<Self> {
        match byte {
            0x1 => Ok(Self::Text),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported websocket opcode",
            )),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum WebSocketFrame {
    Text(String),
    Binary(Vec<u8>),
    Close,
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

struct WebSocketRead {
    buffered: Vec<u8>,
    offset: usize,
}

impl WebSocketRead {
    fn new(buffered: Vec<u8>) -> Self {
        Self {
            buffered,
            offset: 0,
        }
    }

    async fn read_exact(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
        buf: &mut [u8],
    ) -> io::Result<()> {
        let buffered_len = self.buffered.len().saturating_sub(self.offset);
        let prefix_len = buffered_len.min(buf.len());
        if prefix_len > 0 {
            buf[..prefix_len]
                .copy_from_slice(&self.buffered[self.offset..self.offset + prefix_len]);
            self.offset += prefix_len;
        }
        if prefix_len == buf.len() {
            return Ok(());
        }
        stream.read_exact(&mut buf[prefix_len..]).await.map(|_| ())
    }

    async fn read_frame(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> io::Result<WebSocketFrame> {
        read_websocket_frame(self, stream).await
    }
}

async fn read_websocket_frame(
    reader: &mut WebSocketRead,
    stream: &mut (impl AsyncRead + Unpin),
) -> io::Result<WebSocketFrame> {
    let mut header = [0u8; 2];
    reader.read_exact(stream, &mut header).await?;

    let fin = header[0] & 0x80 != 0;
    if !fin {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fragmented websocket frames are not supported",
        ));
    }

    let opcode = WebSocketOpcode::from_byte(header[0] & 0x0f)?;
    let masked = header[1] & 0x80 != 0;
    if !masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client websocket frames must be masked",
        ));
    }

    let len_marker = header[1] & 0x7f;
    let payload_len = match len_marker {
        0..=125 => u64::from(len_marker),
        126 => {
            let mut len = [0u8; 2];
            reader.read_exact(stream, &mut len).await?;
            u64::from(u16::from_be_bytes(len))
        }
        127 => {
            let mut len = [0u8; 8];
            reader.read_exact(stream, &mut len).await?;
            u64::from_be_bytes(len)
        }
        _ => unreachable!(),
    };
    if payload_len > MAX_WEBSOCKET_PAYLOAD_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket payload too large",
        ));
    }

    if matches!(opcode, WebSocketOpcode::Ping | WebSocketOpcode::Pong) && payload_len > 125 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket control payload too large",
        ));
    }

    let mut mask = [0u8; 4];
    reader.read_exact(stream, &mut mask).await?;

    let mut payload = vec![0u8; payload_len as usize];
    reader.read_exact(stream, &mut payload).await?;
    simd::xor_mask(&mut payload, mask);

    match opcode {
        WebSocketOpcode::Text => {
            let text = String::from_utf8(payload).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid websocket text frame")
            })?;
            Ok(WebSocketFrame::Text(text))
        }
        WebSocketOpcode::Binary => Ok(WebSocketFrame::Binary(payload)),
        WebSocketOpcode::Close => Ok(WebSocketFrame::Close),
        WebSocketOpcode::Ping => Ok(WebSocketFrame::Ping(payload)),
        WebSocketOpcode::Pong => Ok(WebSocketFrame::Pong(payload)),
    }
}

async fn write_websocket_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    opcode: WebSocketOpcode,
    payload: &[u8],
) -> io::Result<()> {
    let mut header = Vec::with_capacity(10);
    header.push(0x80 | opcode as u8);
    match payload.len() {
        0..=125 => header.push(payload.len() as u8),
        126..=65535 => {
            header.push(126);
            header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            header.push(127);
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    stream.write_all(&header).await?;
    stream.write_all(payload).await
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    simd::find_header_end(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use shitspeak_auth::{AuthenticateResult, AuthenticationExpiryAction, AuthenticationRejection};
    use shitspeak_runtime::localization::Language;

    #[test]
    fn web_event_conversion_preserves_move_messages_and_omits_permission_queries() {
        let session = ClientSessionIdentifier::from(42);
        let messages: Vec<Message> = vec![
            shitspeak_runtime::messages::encoder::ChannelState {
                channel_id: Some(10),
                parent: Some(0),
                name: Some("Hidden parent".to_string()),
                ..Default::default()
            }
            .into(),
            shitspeak_runtime::messages::encoder::ChannelState {
                channel_id: Some(11),
                parent: Some(10),
                name: Some("Hidden destination".to_string()),
                ..Default::default()
            }
            .into(),
            shitspeak_runtime::messages::encoder::PermissionQuery::refresh_channel_permissions(
                11, 0,
            )
            .into(),
            shitspeak_runtime::messages::encoder::UserState {
                session: Some(session),
                channel_id: Some(11),
                ..Default::default()
            }
            .into(),
            shitspeak_runtime::messages::encoder::ChannelRemove { channel_id: 11 }.into(),
            shitspeak_runtime::messages::encoder::ChannelRemove { channel_id: 10 }.into(),
        ];

        let events = messages
            .into_iter()
            .filter_map(server_event_from_message)
            .collect::<Vec<_>>();

        assert!(matches!(
            &events[0],
            ServerEvent::ChannelState(channel) if channel.channel_id == Some(10)
        ));
        assert!(matches!(
            &events[1],
            ServerEvent::ChannelState(channel) if channel.channel_id == Some(11)
        ));
        assert!(matches!(
            &events[2],
            ServerEvent::UserState(user)
                if user.session == Some(u32::from(session)) && user.channel_id == Some(11)
        ));
        assert!(matches!(
            &events[3],
            ServerEvent::ChannelRemove { channel_id: 11 }
        ));
        assert!(matches!(
            &events[4],
            ServerEvent::ChannelRemove { channel_id: 10 }
        ));
        assert_eq!(events.len(), 5, "PermissionQuery must remain native-only");
    }

    const TEST_WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    #[test]
    fn finds_http_header_end() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\n\n"), None);
    }

    #[test]
    fn computes_websocket_accept_key() {
        assert_eq!(
            websocket_accept_key(TEST_WEBSOCKET_KEY),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn negotiated_speaker_slots_are_capped_by_server_limit() {
        assert_eq!(negotiated_speaker_slots(None, 8), 8);
        assert_eq!(negotiated_speaker_slots(Some(4), 8), 4);
        assert_eq!(negotiated_speaker_slots(Some(64), 8), 8);
        assert_eq!(negotiated_speaker_slots(Some(0), 8), 1);
        assert_eq!(negotiated_speaker_slots(Some(0), 0), 1);
    }

    #[test]
    fn visibility_reload_receiver_drains_queued_notifications() {
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let mut rx = Some(rx);
        tx.send(()).unwrap();
        tx.send(()).unwrap();

        assert!(drain_visibility_reload_receiver(&mut rx));
        assert!(!drain_visibility_reload_receiver(&mut rx));

        drop(tx);
        assert!(!drain_visibility_reload_receiver(&mut rx));
        assert!(rx.is_none());
    }

    #[tokio::test]
    async fn health_response_over_generic_stream() {
        let (mut client, server) = tokio::io::duplex(1024);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            ..Default::default()
        });
        let handle = tokio::spawn(async move { signaling.handle_stream(server).await });

        client
            .write_all(b"GET /web/health HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        handle.await.unwrap().unwrap();

        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains(r#"{"status":"ok"}"#));
    }

    #[tokio::test]
    async fn websocket_upgrade_returns_switching_protocols() {
        let (mut client, server) = tokio::io::duplex(2048);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            ..Default::default()
        });
        let handle = tokio::spawn(async move { signaling.handle_stream(server).await });

        client
            .write_all(websocket_upgrade_request().as_bytes())
            .await
            .unwrap();
        let response = read_http_response_header(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));
        assert!(response.contains("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

        assert_default_gateway_config(&mut client).await;

        client.write_all(&masked_close_frame()).await.unwrap();
        let frame = read_server_frame(&mut client).await;
        assert_eq!(frame, WebSocketFrame::Close);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn signaling_requires_websocket_upgrade() {
        let (mut client, server) = tokio::io::duplex(2048);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            ..Default::default()
        });
        let handle = tokio::spawn(async move { signaling.handle_stream(server).await });

        client
            .write_all(b"GET /web/signaling HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        handle.await.unwrap().unwrap();

        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains(r#"{"error":"websocket upgrade required"}"#));
    }

    #[tokio::test]
    async fn websocket_offer_with_invalid_sdp_reports_answer_error() {
        let (mut client, server) = tokio::io::duplex(4096);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            auth: shitspeak_runtime_config::WebAuthConfig {
                password_enabled: false,
                modes: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        });
        let handle = tokio::spawn(async move { signaling.handle_stream(server).await });

        let payload = r#"{"type":"offer","sdp":"v=0"}"#;
        let mut request = websocket_upgrade_request().into_bytes();
        request.extend_from_slice(&masked_text_frame(payload));
        client.write_all(&request).await.unwrap();

        let response = read_http_response_header(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

        assert_default_gateway_config(&mut client).await;

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        assert_eq!(
            event,
            ServerEvent::Error {
                message: "failed to answer webrtc offer: SdpInvalidSyntax: ".to_string()
            }
        );

        client.write_all(&masked_close_frame()).await.unwrap();
        let frame = read_server_frame(&mut client).await;
        assert_eq!(frame, WebSocketFrame::Close);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn websocket_offer_returns_webrtc_answer() {
        let mut media_engine = webrtc::api::media_engine::MediaEngine::default();
        media_engine.register_default_codecs().unwrap();
        let api = webrtc::api::APIBuilder::new()
            .with_media_engine(media_engine)
            .build();
        let offer_peer = api
            .new_peer_connection(
                webrtc::peer_connection::configuration::RTCConfiguration::default(),
            )
            .await
            .unwrap();
        offer_peer
            .create_data_channel("shitspeak-control", None)
            .await
            .unwrap();
        let offer = offer_peer.create_offer(None).await.unwrap();
        offer_peer
            .set_local_description(offer.clone())
            .await
            .unwrap();

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            auth: shitspeak_runtime_config::WebAuthConfig {
                password_enabled: false,
                modes: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        });
        let handle = tokio::spawn(async move { signaling.handle_stream(server).await });

        let payload = serde_json::json!({
            "type": "offer",
            "sdp": offer.sdp,
        })
        .to_string();
        let mut request = websocket_upgrade_request().into_bytes();
        request.extend_from_slice(&masked_text_frame(&payload));
        client.write_all(&request).await.unwrap();

        let response = read_http_response_header(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

        assert_default_gateway_config(&mut client).await;

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let answer: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(answer["type"], "answer");
        assert!(answer["sdp"].as_str().unwrap().starts_with("v=0"));

        client.write_all(&masked_close_frame()).await.unwrap();
        loop {
            let frame = read_server_frame(&mut client).await;
            if frame == WebSocketFrame::Close {
                break;
            }
        }
        offer_peer.close().await.unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn websocket_offer_requires_authentication_when_auth_is_enabled() {
        let (mut client, server) = tokio::io::duplex(4096);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            ..Default::default()
        });
        let handle = tokio::spawn(async move { signaling.handle_stream(server).await });

        let payload = r#"{"type":"offer","sdp":"v=0"}"#;
        let mut request = websocket_upgrade_request().into_bytes();
        request.extend_from_slice(&masked_text_frame(payload));
        client.write_all(&request).await.unwrap();

        let response = read_http_response_header(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

        assert_default_gateway_config(&mut client).await;

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        assert_eq!(
            event,
            ServerEvent::Error {
                message: "authentication required before webrtc offer".to_string()
            }
        );

        client.write_all(&masked_close_frame()).await.unwrap();
        let frame = read_server_frame(&mut client).await;
        assert_eq!(frame, WebSocketFrame::Close);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn websocket_password_authenticates_through_authenticator() {
        let (mut client, server) = tokio::io::duplex(4096);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            ..Default::default()
        })
        .with_authenticator(Arc::new(TestAuthenticator::default_session()));
        let handle = tokio::spawn(async move { signaling.handle_stream(server).await });

        let payload = r#"{"type":"authenticate","auth":{"password":{"username":"alice","password":"secret"}}}"#;
        let mut request = websocket_upgrade_request().into_bytes();
        request.extend_from_slice(&masked_text_frame(payload));
        client.write_all(&request).await.unwrap();

        let response = read_http_response_header(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

        assert_default_gateway_config(&mut client).await;

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        assert_eq!(
            text,
            r#"{"type":"authenticated","session":0,"display_name":"Alice"}"#
        );

        client.write_all(&masked_close_frame()).await.unwrap();
        let frame = read_server_frame(&mut client).await;
        assert_eq!(frame, WebSocketFrame::Close);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn websocket_password_auth_reports_rejection() {
        let (mut client, server) = tokio::io::duplex(4096);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            ..Default::default()
        })
        .with_authenticator(Arc::new(TestAuthenticator::default_session()));
        let handle = tokio::spawn(async move { signaling.handle_stream(server).await });

        let payload =
            r#"{"type":"authenticate","auth":{"password":{"username":"alice","password":"bad"}}}"#;
        let mut request = websocket_upgrade_request().into_bytes();
        request.extend_from_slice(&masked_text_frame(payload));
        client.write_all(&request).await.unwrap();

        let response = read_http_response_header(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

        assert_default_gateway_config(&mut client).await;

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        assert_eq!(
            text,
            r#"{"type":"authentication_rejected","reason":"wrong password"}"#
        );

        client.write_all(&masked_close_frame()).await.unwrap();
        let frame = read_server_frame(&mut client).await;
        assert_eq!(frame, WebSocketFrame::Close);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn websocket_password_auth_allocates_server_client() {
        let server = test_server_with_authenticator(TestAuthenticator::default_session()).await;
        let (mut client, server_stream) = tokio::io::duplex(4096);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            ..Default::default()
        })
        .with_authenticator(Arc::new(TestAuthenticator::allocated_session()))
        .with_server(Arc::clone(&server));
        let handle = tokio::spawn(async move { signaling.handle_stream(server_stream).await });

        let payload = r#"{"type":"authenticate","auth":{"password":{"username":"alice","password":"secret"}}}"#;
        let mut request = websocket_upgrade_request().into_bytes();
        request.extend_from_slice(&masked_text_frame(payload));
        client.write_all(&request).await.unwrap();

        let response = read_http_response_header(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

        assert_default_gateway_config(&mut client).await;

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        let ServerEvent::Authenticated { session, .. } = event else {
            panic!("expected authenticated event");
        };
        assert_ne!(session, DEFAULT_WEB_SESSION_ID);
        assert_eq!(server.get_clients().local_len().await, 1);

        let authenticated_client = server
            .get_clients()
            .get_client(ClientSessionIdentifier::from(session))
            .await
            .expect("authenticated web client");
        {
            let extended = authenticated_client.user_info_extended().await;
            let credential = extended.get_credential().as_ref().expect("credential");
            assert_eq!(credential.username, "alice");
            assert_eq!(credential.password.as_deref(), Some("secret"));
        }
        {
            let local = authenticated_client.read_local_state();
            let local = local.as_ref().expect("local state");
            assert_eq!(local.auth_session_id(), Some("web-auth-session"));
            assert_eq!(
                local.authentication_expiry_action(),
                AuthenticationExpiryAction::Reauth
            );
            assert!(local.authenticated_until().is_some());
        }

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        let ServerEvent::ChannelState(channel) = event else {
            panic!("expected initial root channel state");
        };
        assert_eq!(channel.channel_id, Some(0));

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        let ServerEvent::UserState(user) = event else {
            panic!("expected initial self user state");
        };
        assert_eq!(user.session, Some(session));
        assert_eq!(user.name.as_deref(), Some("Alice"));
        assert_eq!(user.user_id, Some(7));
        assert_eq!(user.channel_id, Some(0));

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        let ServerEvent::ServerSync(sync) = event else {
            panic!("expected server sync");
        };
        assert_eq!(sync.session, Some(session));

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        assert!(matches!(event, ServerEvent::ServerConfig(_)));

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        assert!(matches!(event, ServerEvent::CodecVersion(_)));

        client.write_all(&masked_close_frame()).await.unwrap();
        let frame = read_server_frame(&mut client).await;
        assert_eq!(frame, WebSocketFrame::Close);
        handle.await.unwrap().unwrap();
        assert_eq!(server.get_clients().local_len().await, 0);
    }

    #[tokio::test]
    async fn websocket_join_channel_command_uses_server_handlers() {
        let server = test_server_with_authenticator(TestAuthenticator::default_session()).await;
        server
            .get_channels()
            .create_channel(shitspeak_state::Channel::new(1, "Lobby", 0, 0, Some(0)))
            .await
            .unwrap();

        let (mut client, server_stream) = tokio::io::duplex(8192);
        let signaling = SignalingServer::new(WebConfig {
            enabled: true,
            ..Default::default()
        })
        .with_authenticator(Arc::new(TestAuthenticator::allocated_session()))
        .with_server(Arc::clone(&server));
        let handle = tokio::spawn(async move { signaling.handle_stream(server_stream).await });

        let payload = r#"{"type":"authenticate","auth":{"password":{"username":"alice","password":"secret"}}}"#;
        let mut request = websocket_upgrade_request().into_bytes();
        request.extend_from_slice(&masked_text_frame(payload));
        client.write_all(&request).await.unwrap();

        let response = read_http_response_header(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));

        assert_default_gateway_config(&mut client).await;

        let frame = read_server_frame(&mut client).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        let ServerEvent::Authenticated { session, .. } = event else {
            panic!("expected authenticated event");
        };

        let mut saw_sync = false;
        for _ in 0..8 {
            let frame = read_server_frame(&mut client).await;
            let WebSocketFrame::Text(text) = frame else {
                panic!("expected text frame");
            };
            let event: ServerEvent = serde_json::from_str(&text).unwrap();
            if matches!(event, ServerEvent::ServerSync(_)) {
                saw_sync = true;
                break;
            }
        }
        assert!(saw_sync, "expected initial server sync before command");

        client
            .write_all(&masked_text_frame(
                r#"{"type":"join_channel","channel_id":1}"#,
            ))
            .await
            .unwrap();

        let mut saw_move = false;
        for _ in 0..8 {
            let frame = read_server_frame(&mut client).await;
            let WebSocketFrame::Text(text) = frame else {
                panic!("expected text frame");
            };
            let event: ServerEvent = serde_json::from_str(&text).unwrap();
            if let ServerEvent::UserState(user) = event {
                if user.session == Some(session) && user.channel_id == Some(1) {
                    saw_move = true;
                    break;
                }
            }
        }
        assert!(saw_move, "expected self user state update");

        client.write_all(&masked_close_frame()).await.unwrap();
        let frame = read_server_frame(&mut client).await;
        assert_eq!(frame, WebSocketFrame::Close);
        handle.await.unwrap().unwrap();
    }

    fn websocket_upgrade_request() -> String {
        format!(
            "GET /web/signaling HTTP/1.1\r\n\
             host: localhost\r\n\
             upgrade: websocket\r\n\
             connection: keep-alive, Upgrade\r\n\
             sec-websocket-key: {TEST_WEBSOCKET_KEY}\r\n\
             sec-websocket-version: 13\r\n\
             \r\n"
        )
    }

    fn masked_text_frame(payload: &str) -> Vec<u8> {
        masked_frame(WebSocketOpcode::Text, payload.as_bytes())
    }

    fn masked_close_frame() -> Vec<u8> {
        masked_frame(WebSocketOpcode::Close, &[])
    }

    fn masked_frame(opcode: WebSocketOpcode, payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = Vec::new();
        frame.push(0x80 | opcode as u8);
        match payload.len() {
            0..=125 => frame.push(0x80 | payload.len() as u8),
            126..=65535 => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            _ => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ mask[i % 4]),
        );
        frame
    }

    async fn read_http_response_header(stream: &mut (impl AsyncRead + Unpin)) -> String {
        let mut response = Vec::new();
        let mut scratch = [0u8; 1];
        loop {
            stream.read_exact(&mut scratch).await.unwrap();
            response.extend_from_slice(&scratch);
            if find_header_end(&response).is_some() {
                break;
            }
        }
        String::from_utf8(response).unwrap()
    }

    async fn read_server_frame(stream: &mut (impl AsyncRead + Unpin)) -> WebSocketFrame {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0] & 0x80, 0x80);
        let opcode = WebSocketOpcode::from_byte(header[0] & 0x0f).unwrap();
        assert_eq!(header[1] & 0x80, 0);
        let payload_len = match header[1] & 0x7f {
            0..=125 => usize::from(header[1] & 0x7f),
            126 => {
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).await.unwrap();
                usize::from(u16::from_be_bytes(len))
            }
            127 => {
                let mut len = [0u8; 8];
                stream.read_exact(&mut len).await.unwrap();
                usize::try_from(u64::from_be_bytes(len)).unwrap()
            }
            _ => unreachable!(),
        };
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await.unwrap();
        match opcode {
            WebSocketOpcode::Text => WebSocketFrame::Text(String::from_utf8(payload).unwrap()),
            WebSocketOpcode::Binary => WebSocketFrame::Binary(payload),
            WebSocketOpcode::Close => WebSocketFrame::Close,
            WebSocketOpcode::Ping => WebSocketFrame::Ping(payload),
            WebSocketOpcode::Pong => WebSocketFrame::Pong(payload),
        }
    }

    async fn assert_default_gateway_config(stream: &mut (impl AsyncRead + Unpin)) {
        let frame = read_server_frame(stream).await;
        let WebSocketFrame::Text(text) = frame else {
            panic!("expected text frame");
        };
        let event: ServerEvent = serde_json::from_str(&text).unwrap();
        assert_eq!(
            event,
            ServerEvent::GatewayConfig(WebGatewayConfig {
                max_speaker_slots: 64,
                audio_bitrate: 64_000,
                transports: vec![WebTransportKind::WebRtc],
                moq: None,
            })
        );
    }

    struct TestAuthenticator {
        expected_session: ExpectedAuthSession,
    }

    #[derive(Clone, Copy)]
    enum ExpectedAuthSession {
        Default,
        Allocated,
    }

    impl TestAuthenticator {
        fn default_session() -> Self {
            Self {
                expected_session: ExpectedAuthSession::Default,
            }
        }

        fn allocated_session() -> Self {
            Self {
                expected_session: ExpectedAuthSession::Allocated,
            }
        }
    }

    #[async_trait]
    impl Authenticator for TestAuthenticator {
        async fn authenticate(
            &self,
            username: &str,
            password: Option<&str>,
            auxiliary_data: &AuthenticateAuxiliaryData,
        ) -> Result<AuthenticateResult, AuthenticationRejection> {
            match self.expected_session {
                ExpectedAuthSession::Default => {
                    assert_eq!(auxiliary_data.session_id, DEFAULT_WEB_SESSION_ID)
                }
                ExpectedAuthSession::Allocated => {
                    assert_ne!(auxiliary_data.session_id, DEFAULT_WEB_SESSION_ID)
                }
            }
            assert_eq!(auxiliary_data.ip_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
            if username != "alice" {
                return Err(AuthenticationRejection::NoSuchUser);
            }
            if password != Some("secret") {
                return Err(AuthenticationRejection::WrongPassword);
            }
            Ok(AuthenticateResult {
                auth_session_id: Some("web-auth-session".to_string()),
                authenticated_until: Some(
                    "2099-01-01T00:00:00Z"
                        .parse()
                        .expect("valid authentication expiry"),
                ),
                authentication_expiry_action: AuthenticationExpiryAction::Reauth,
                user_id: Some(7),
                fqdn: None,
                display_name: Some("Alice".to_string()),
                groups: vec!["web".to_string()],
                is_superuser: false,
                virtual_server_id: None,
                language: Language::default(),
                max_bandwidth: None,
                texture_url: None,
                comment_url: None,
            })
        }
    }

    async fn test_server_with_authenticator<A: Authenticator>(
        authenticator: A,
    ) -> Arc<Box<Server>> {
        static CRYPTO_PROVIDER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        CRYPTO_PROVIDER.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let config = shitspeak_runtime_config::Config {
            listen: "127.0.0.1:0".into(),
            server_entrypoints: Vec::new(),
            register_name: "test".into(),
            register_password: None,
            register_url: None,
            register_hostname: None,
            register_location: None,
            cert_path: cert_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
            send_version: false,
            send_build_info: false,
            send_os_info: false,
            server_protocol_version: shitspeak_runtime::constants::APP_PROTO_VER,
            allowed_proxies: Vec::new(),
            min_client_version: 0,
            max_users: 100,
            authenticator: shitspeak_runtime_config::AuthenticatorConfig::default(),
            observability: shitspeak_runtime_config::ObservabilityConfig::default(),
            geoip: shitspeak_runtime_config::GeoIpConfig::default(),
            welcome_text: None,
            max_bandwidth: 72_000,
            allow_html: true,
            max_text_message_length: 5_000,
            max_image_message_length: 131_072,
            root_channel_name: "Root".into(),
            default_channel: 0,
            cert_required: false,
            blob_storage_dir: None,
            user_channel_cache_record_remote_sessions: false,
            channel_log_max_entries: 10_000,
            client_log_max_entries: 10_000,
            channel_snapshot_every_ops: 10,
            channel_snapshot_every_secs: 60,
            channel_wal_compaction_expire_count: 2_000,
            udp_voice_enabled: false,
            udp_ping_enabled: false,
            udp_ping_user_count_scope: shitspeak_runtime_config::UdpPingUserCountScope::Cluster,
            udp_channel_size: 2_048,
            client_idle_timeout_secs: 30,
            authenticate_timeout_ms: 30_000,
            auth_finalization_concurrency: 4,
            pending_delete_timeout_ms: 5_000,
            required_groups: Default::default(),
            send_permission_info: false,
            hide_users_without_traverse: false,
            hide_channels_without_traverse: false,
            show_node_id_for_superusers: true,
            acl: shitspeak_runtime_config::AclConfig::default(),
            privacy: shitspeak_runtime_config::PrivacyConfig::default(),
            s2s: shitspeak_runtime_config::S2sConfig::default(),
            web: WebConfig::default(),
            voice: shitspeak_runtime_config::VoiceTuning::default(),
        };

        Server::new(config, authenticator).await.unwrap()
    }
}
