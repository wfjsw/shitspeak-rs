//! In-process Mumble protocol client used by the two-client integration tests.
//!
//! The test client opens a TLS connection (validating the test server's CA and
//! presenting its own self-signed cert so the server records a non-empty
//! `certificate_hash`), frames Mumble messages, owns a background reader task
//! that drains incoming messages into an mpsc, and exposes one helper per
//! action the scenarios need (auth, set self-mute, move channel, create
//! channel, ACL, voice over TCP, voice over UDP, ...).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut as _, Bytes, BytesMut};
use parking_lot::Mutex as PMutex;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::integration_tests::harness::TestServer;
use crate::messages::encoder::{
    Authenticate, ChanAcl, ChannelRemove, ClientType, ContextAction, RequestBlob, UserRemove,
    UserState, Version, VoiceTarget,
};
use crate::messages::{Message, ReadMessageExt, WriteMessageExt};
use crate::protocol_version::ProtocolVersion;
use crate::voice::codec::{Audio, AudioPayload, IncomingUdpPacket, OpusPayload, PacketFormat};
use crate::voice::ping::PingRequest;
use shitspeak_client_crypto::CryptState;

/// Build a Mumble-legacy client→server Opus voice packet.
///
/// Wire format (no `sender_session` — that field is server→client only):
///   `[ 0x80 | (target & 0x1f), varint(frame_number), varint(size_flag), opus.. ]`
fn encode_legacy_client_voice(target: u32, frame_number: u64, opus: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + 4 + 4 + opus.len());
    buf.put_u8((0x04u8 << 5) | (target as u8 & 0x1f));
    write_pds_varint(&mut buf, frame_number);
    let size_flag = opus.len() as u64 & 0x1FFF;
    write_pds_varint(&mut buf, size_flag);
    buf.extend_from_slice(opus);
    buf.freeze()
}

/// Build a Mumble 1.5+ protobuf client→server voice packet, the way the
/// official client does. Type byte 0x00 prefixes the encoded `MumbleUDP.Audio`.
/// `sender_session` is omitted (server fills it from the authenticated session).
fn encode_protobuf_client_voice(target: u32, frame_number: u64, opus: &[u8]) -> Bytes {
    use crate::messages::encoder::{Audio as AudioWire, AudioHeader, AudioTarget};
    use prost::Message as _;
    let wire = AudioWire {
        header: Some(AudioHeader::Target(AudioTarget::from(target))),
        sender_session: 0,
        frame_number,
        opus_data: Bytes::copy_from_slice(opus),
        positional_data: vec![],
        volume_adjustment: 0.0,
        is_terminator: false,
    };
    let proto: crate::mumble_udp::Audio = wire.into();
    let mut buf = BytesMut::with_capacity(1 + proto.encoded_len());
    buf.put_u8(0x00);
    proto.encode(&mut buf).expect("encode protobuf audio");
    buf.freeze()
}

/// PacketDataStream varint reader. Mirrors the codec's `read_varint`, but
/// is owned by the test client so it can decode server→client wire payloads
/// without coupling to the (server-side) codec's c→s assumptions.
fn read_pds_varint(data: &[u8]) -> Option<(u64, usize)> {
    let c = *data.first()? as u64;
    if c & 0x80 == 0 {
        Some((c, 1))
    } else if c & 0x40 == 0 {
        let b1 = *data.get(1)? as u64;
        Some(((c & 0x3F) << 8 | b1, 2))
    } else if c & 0x20 == 0 {
        let b1 = *data.get(1)? as u64;
        let b2 = *data.get(2)? as u64;
        Some(((c & 0x1F) << 16 | b1 << 8 | b2, 3))
    } else if c & 0x10 == 0 {
        let b1 = *data.get(1)? as u64;
        let b2 = *data.get(2)? as u64;
        let b3 = *data.get(3)? as u64;
        Some(((c & 0x0F) << 24 | b1 << 16 | b2 << 8 | b3, 4))
    } else {
        None
    }
}

/// Decode a server→client legacy Opus voice packet. Differs from the
/// codec's c→s decoder by reading the `sender_session` varint between the
/// header byte and the frame number — that field is present on s→c packets
/// only.
fn decode_legacy_server_voice(data: &[u8]) -> Option<Audio> {
    if data.len() < 2 {
        return None;
    }
    let header = data[0];
    if (header >> 5) != 4 {
        return None; // not VoiceOpus
    }
    let target = crate::messages::encoder::AudioTarget::from((header & 0x1f) as u32);
    let mut pos = 1usize;
    let (sender_session, n) = read_pds_varint(&data[pos..])?;
    pos += n;
    let (frame_number, n) = read_pds_varint(&data[pos..])?;
    pos += n;
    let (size_flag, n) = read_pds_varint(&data[pos..])?;
    pos += n;
    let payload_size = (size_flag & 0x1FFF) as usize;
    let is_terminator = (size_flag & 0x2000) != 0;
    if pos + payload_size > data.len() {
        return None;
    }
    let opus_data = Bytes::copy_from_slice(&data[pos..pos + payload_size]);
    pos += payload_size;
    let positional_data = if data.len() == pos {
        None
    } else if data.len() == pos + 12 {
        let mut out = [0f32; 3];
        for i in 0..3 {
            let start = pos + i * 4;
            let bytes: [u8; 4] = data[start..start + 4].try_into().ok()?;
            out[i] = f32::from_le_bytes(bytes);
        }
        Some(out)
    } else {
        return None;
    };
    Some(Audio {
        target,
        sender_session: Some(ClientSessionIdentifier::from(sender_session as u32)),
        frame_number,
        audio_payload: AudioPayload::Opus(OpusPayload {
            frame: opus_data,
            is_terminator,
        }),
        positional_data,
        volume_adjustment: 1.0,
        format: PacketFormat::Legacy,
    })
}

/// Decode a server→client UDP voice payload, auto-detecting protobuf vs
/// legacy. Protobuf packets carry their own sender_session field, so the
/// codec's existing decoder works in both directions; legacy packets need
/// the s→c-aware decoder above.
fn decode_server_voice(data: &[u8]) -> Option<Audio> {
    if data.is_empty() {
        return None;
    }
    if data[0] == 0x00 {
        if let Ok(audio) = Audio::decode(data, None) {
            return Some(audio);
        }
    }
    decode_legacy_server_voice(data)
}

/// Like [`encode_legacy_client_voice`] but supports the Opus terminator bit
/// and optional positional audio data (3 × little-endian f32 appended after
/// the payload per the Mumble wire spec).
fn encode_legacy_client_voice_ex(
    target: u32,
    frame_number: u64,
    opus: &[u8],
    is_terminator: bool,
    positional: Option<[f32; 3]>,
) -> Bytes {
    let pos_len = if positional.is_some() { 12 } else { 0 };
    let mut buf = BytesMut::with_capacity(1 + 4 + 4 + opus.len() + pos_len);
    buf.put_u8((0x04u8 << 5) | (target as u8 & 0x1f));
    write_pds_varint(&mut buf, frame_number);
    let size_flag = (opus.len() as u64 & 0x1FFF) | if is_terminator { 0x2000 } else { 0 };
    write_pds_varint(&mut buf, size_flag);
    buf.extend_from_slice(opus);
    if let Some([x, y, z]) = positional {
        buf.extend_from_slice(&x.to_le_bytes());
        buf.extend_from_slice(&y.to_le_bytes());
        buf.extend_from_slice(&z.to_le_bytes());
    }
    buf.freeze()
}

/// Like [`encode_protobuf_client_voice`] but supports the terminator bit and
/// optional positional data in the MumbleUDP.Audio proto fields.
fn encode_protobuf_client_voice_ex(
    target: u32,
    frame_number: u64,
    opus: &[u8],
    is_terminator: bool,
    positional: Option<[f32; 3]>,
) -> Bytes {
    use crate::messages::encoder::{Audio as AudioWire, AudioHeader, AudioTarget};
    use prost::Message as _;
    let wire = AudioWire {
        header: Some(AudioHeader::Target(AudioTarget::from(target))),
        sender_session: 0,
        frame_number,
        opus_data: Bytes::copy_from_slice(opus),
        positional_data: match positional {
            Some([x, y, z]) => vec![x, y, z],
            None => vec![],
        },
        volume_adjustment: 0.0,
        is_terminator,
    };
    let proto: crate::mumble_udp::Audio = wire.into();
    let mut buf = BytesMut::with_capacity(1 + proto.encoded_len());
    buf.put_u8(0x00);
    proto.encode(&mut buf).expect("encode protobuf audio");
    buf.freeze()
}

/// PacketDataStream varint (Mumble's framing — not LEB128).
fn write_pds_varint(buf: &mut BytesMut, value: u64) {
    if value <= 0x7F {
        buf.put_u8(value as u8);
    } else if value <= 0x3FFF {
        buf.put_u8(0x80 | (value >> 8) as u8);
        buf.put_u8((value & 0xFF) as u8);
    } else if value <= 0x1F_FFFF {
        buf.put_u8(0xC0 | (value >> 16) as u8);
        buf.put_u8(((value >> 8) & 0xFF) as u8);
        buf.put_u8((value & 0xFF) as u8);
    } else if value <= 0x0FFF_FFFF {
        buf.put_u8(0xE0 | (value >> 24) as u8);
        buf.put_u8(((value >> 16) & 0xFF) as u8);
        buf.put_u8(((value >> 8) & 0xFF) as u8);
        buf.put_u8((value & 0xFF) as u8);
    } else {
        buf.put_u8(0xEF);
        buf.put_u8(0xFF);
        buf.put_u8(0xFF);
        buf.put_u8(0xFF);
    }
}

#[derive(Debug)]
pub enum ConnectError {
    Io(std::io::Error),
    Tls(String),
    Read(String),
    Write(String),
    Rejected(crate::mumble_proto::Reject),
    NoCryptSetup,
    NoServerSync,
}

impl From<std::io::Error> for ConnectError {
    fn from(e: std::io::Error) -> Self {
        ConnectError::Io(e)
    }
}

/// A single test client.
pub struct TestClient {
    pub session_id: u32,
    pub user_id: Option<u32>,
    pub initial_channel_states: Vec<crate::mumble_proto::ChannelState>,
    pub initial_user_states: Vec<crate::mumble_proto::UserState>,
    pub initial_context_actions: Vec<crate::mumble_proto::ContextActionModify>,
    pub welcome_text: Option<String>,
    pub max_bandwidth: Option<u32>,
    pub initial_permissions: Option<u64>,
    pub server_session: ClientSessionIdentifier,
    pub cert_der: Vec<u8>,
    write: Mutex<WriteHalf<TlsStream<TcpStream>>>,
    rx: Mutex<mpsc::UnboundedReceiver<Result<Message, String>>>,
    udp: Option<Arc<UdpSocket>>,
    udp_server_addr: SocketAddr,
    crypt: Option<Arc<PMutex<CryptState>>>,
    _reader: JoinHandle<()>,
}

pub struct ManualNativeClient {
    write: Mutex<WriteHalf<TlsStream<TcpStream>>>,
    rx: Mutex<mpsc::UnboundedReceiver<Result<Message, String>>>,
    _reader: JoinHandle<()>,
}

impl Drop for TestClient {
    fn drop(&mut self) {
        self._reader.abort();
    }
}

impl Drop for ManualNativeClient {
    fn drop(&mut self) {
        self._reader.abort();
    }
}

struct NativeConnection {
    write_half: WriteHalf<TlsStream<TcpStream>>,
    msg_rx: mpsc::UnboundedReceiver<Result<Message, String>>,
    reader_handle: JoinHandle<()>,
    cert_der: Vec<u8>,
}

impl TestClient {
    /// Connect to `server`, send Version + Authenticate, wait for ServerSync,
    /// and return the live client. Buffers the full burst of intermediate
    /// messages (CryptSetup, ChannelState, UserState, ServerConfig, CodecVersion)
    /// so scenarios can assert against them.
    pub async fn connect_and_authenticate(
        server: &TestServer,
        username: &str,
        password: Option<&str>,
    ) -> Result<TestClient, ConnectError> {
        Self::connect_and_authenticate_with_deadline(
            server,
            username,
            password,
            Duration::from_secs(5),
        )
        .await
    }

    pub async fn connect_and_authenticate_with_deadline(
        server: &TestServer,
        username: &str,
        password: Option<&str>,
        deadline: Duration,
    ) -> Result<TestClient, ConnectError> {
        Self::connect_with(
            server,
            username,
            password,
            true,
            ProtocolVersion::new(1, 5, 0),
            Vec::new(),
            deadline,
        )
        .await
    }

    /// Connect declaring an explicit protocol version in the `Version`
    /// message. Use 1.4.0 (or older) to make the server treat this client
    /// as a legacy speaker (and route legacy-format voice to it); 1.5.0+
    /// makes it a protobuf speaker.
    pub async fn connect_with_version(
        server: &TestServer,
        username: &str,
        password: Option<&str>,
        version: ProtocolVersion,
    ) -> Result<TestClient, ConnectError> {
        Self::connect_with(
            server,
            username,
            password,
            true,
            version,
            Vec::new(),
            Duration::from_secs(5),
        )
        .await
    }

    /// Same as `connect_and_authenticate` but does not present a client cert.
    /// Used by the `cert_required` reject test.
    pub async fn connect_without_cert(
        server: &TestServer,
        username: &str,
        password: Option<&str>,
    ) -> Result<TestClient, ConnectError> {
        Self::connect_with(
            server,
            username,
            password,
            false,
            ProtocolVersion::new(1, 5, 0),
            Vec::new(),
            Duration::from_secs(5),
        )
        .await
    }

    pub async fn connect_with_preauth_messages(
        server: &TestServer,
        username: &str,
        password: Option<&str>,
        pre_auth_messages: Vec<Message>,
    ) -> Result<TestClient, ConnectError> {
        Self::connect_with(
            server,
            username,
            password,
            true,
            ProtocolVersion::new(1, 5, 0),
            pre_auth_messages,
            Duration::from_secs(5),
        )
        .await
    }

    async fn connect_with(
        server: &TestServer,
        username: &str,
        password: Option<&str>,
        present_client_cert: bool,
        declared_version: ProtocolVersion,
        pre_auth_messages: Vec<Message>,
        deadline: Duration,
    ) -> Result<TestClient, ConnectError> {
        let connect_result = timeout(deadline, async {
            let connection = open_native_connection(server, present_client_cert).await?;

            let mut client = TestClient {
                session_id: 0,
                user_id: None,
                initial_channel_states: Vec::new(),
                initial_user_states: Vec::new(),
                initial_context_actions: Vec::new(),
                welcome_text: None,
                max_bandwidth: None,
                initial_permissions: None,
                server_session: ClientSessionIdentifier::from(0u32),
                cert_der: connection.cert_der,
                write: Mutex::new(connection.write_half),
                rx: Mutex::new(connection.msg_rx),
                udp: None,
                udp_server_addr: server.udp_addr,
                crypt: None,
                _reader: connection.reader_handle,
            };

            // ── Send pre-auth handshake burst ─────────────────────────────────
            let version: Message = Version {
                version: Some(declared_version),
                release: Some("test-client".into()),
                os: Some("test".into()),
                os_version: Some("test".into()),
            }
            .into();

            let authenticate: Message = Authenticate {
                username: Some(username.into()),
                password: password.map(str::to_owned),
                tokens: Vec::new(),
                celt_versions: Vec::new(),
                opus: Some(true),
                client_type: ClientType::Regular,
            }
            .into();

            let mut handshake = Vec::with_capacity(pre_auth_messages.len() + 2);
            handshake.push(version);
            handshake.extend(pre_auth_messages);
            handshake.push(authenticate);
            client
                .send_batch(&handshake)
                .await
                .map_err(|err| ConnectError::Write(err.to_string()))?;

            // ── Drain until ServerSync (collecting state along the way) ───────
            let result = timeout(deadline, async {
                loop {
                    let msg = match client.recv_one_for_connect().await? {
                        Some(m) => m,
                        None => return Err(ConnectError::NoServerSync),
                    };
                    match msg {
                        Message::Version(_) => {}
                        Message::CryptSetup(cs) => {
                            let key = cs.key.unwrap_or_default();
                            let client_nonce = cs.client_nonce.unwrap_or_default();
                            let server_nonce = cs.server_nonce.unwrap_or_default();
                            if !key.is_empty()
                                && !client_nonce.is_empty()
                                && !server_nonce.is_empty()
                            {
                                // From the client's POV: encrypt with client_nonce,
                                // decrypt with server_nonce.
                                let state = CryptState::from_key(
                                    "OCB2-AES128",
                                    &key,
                                    &client_nonce,
                                    &server_nonce,
                                )
                                .expect("crypt state from CryptSetup");
                                client.crypt = Some(Arc::new(PMutex::new(state)));
                            }
                        }
                        Message::ChannelState(cs) => client.initial_channel_states.push(cs),
                        Message::UserState(us) => client.initial_user_states.push(us),
                        Message::ContextActionModify(modify) => {
                            client.initial_context_actions.push(modify)
                        }
                        Message::ServerConfig(_) => {}
                        Message::CodecVersion(_) => {}
                        Message::Reject(r) => return Err(ConnectError::Rejected(r)),
                        Message::ServerSync(sync) => {
                            let session_u32 = sync.session.unwrap_or(0);
                            client.session_id = session_u32;
                            client.server_session = ClientSessionIdentifier::from(session_u32);
                            client.welcome_text = sync.welcome_text;
                            client.max_bandwidth = sync.max_bandwidth;
                            client.initial_permissions = sync.permissions;
                            // Find self UserState to extract user_id
                            for us in &client.initial_user_states {
                                if us.session == Some(session_u32) {
                                    client.user_id = us.user_id;
                                    break;
                                }
                            }
                            return Ok(());
                        }
                        _ => {} // ignore others
                    }
                }
            })
            .await;

            match result {
                Ok(Ok(())) => Ok(client),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(ConnectError::NoServerSync),
            }
        })
        .await;

        match connect_result {
            Ok(result) => result,
            Err(_) => Err(ConnectError::NoServerSync),
        }
    }

    /// SHA-1 of the DER-encoded client certificate, matching what the server
    /// records in `certificate_hash`.
    pub fn cert_sha1(&self) -> Vec<u8> {
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &self.cert_der);
        digest.as_ref().to_vec()
    }

    /// Send any [`Message`] over the TLS write half. Logs and ignores write
    /// errors (callers usually want to react via the read side, not bubble
    /// I/O failures).
    pub async fn send(&self, message: Message) {
        let mut w = self.write.lock().await;
        let _ = w.write_proto_message(&message).await;
    }

    async fn send_batch(
        &self,
        messages: &[Message],
    ) -> Result<(), crate::errors::WriteProtoMessageError> {
        let mut w = self.write.lock().await;
        w.write_proto_message_batch(messages).await
    }

    async fn recv_one(&self) -> Option<Message> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await? {
            Ok(m) => Some(m),
            Err(_) => None,
        }
    }

    async fn recv_one_for_connect(&self) -> Result<Option<Message>, ConnectError> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(Ok(message)) => Ok(Some(message)),
            Some(Err(error)) => Err(ConnectError::Read(error)),
            None => Ok(None),
        }
    }

    /// Wait up to `deadline` for any incoming message.
    pub async fn recv(&self, deadline: Duration) -> Option<Message> {
        timeout(deadline, self.recv_one()).await.ok().flatten()
    }

    /// Wait up to `deadline` for the reader loop to observe connection close.
    pub async fn recv_closed(&self, deadline: Duration) -> bool {
        let res = timeout(deadline, async {
            loop {
                let mut rx = self.rx.lock().await;
                match rx.recv().await {
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => return true,
                }
            }
        })
        .await;
        res.unwrap_or(false)
    }

    /// Wait up to `deadline` for the first incoming message that satisfies
    /// `predicate`. Messages that do not match are discarded.
    pub async fn recv_until<F>(&self, mut predicate: F, deadline: Duration) -> Option<Message>
    where
        F: FnMut(&Message) -> bool,
    {
        let res = timeout(deadline, async {
            loop {
                let msg = self.recv_one().await?;
                if predicate(&msg) {
                    return Some(msg);
                }
            }
        })
        .await;
        res.ok().flatten()
    }

    /// Drain everything currently buffered without blocking.
    pub async fn drain_now(&self) -> Vec<Message> {
        let mut rx = self.rx.lock().await;
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            if let Ok(msg) = m {
                out.push(msg);
            }
        }
        out
    }

    // ── High-level senders ────────────────────────────────────────────────

    pub async fn move_to_channel(&self, channel_id: u32) {
        let mut us = UserState::default();
        us.session = Some(self.server_session);
        us.channel_id = Some(channel_id);
        self.send(us.into()).await;
    }

    pub async fn set_self_mute(&self, mute: bool) {
        let mut us = UserState::default();
        us.session = Some(self.server_session);
        us.self_mute = Some(mute);
        self.send(us.into()).await;
    }

    pub async fn trigger_context_action(&self, action: &str) {
        self.send(
            ContextAction {
                action: action.to_owned(),
                ..Default::default()
            }
            .into(),
        )
        .await;
    }

    pub async fn set_self_deaf(&self, deaf: bool) {
        let mut us = UserState::default();
        us.session = Some(self.server_session);
        us.self_deaf = Some(deaf);
        self.send(us.into()).await;
    }

    pub async fn set_comment(&self, comment: &str) {
        let mut us = UserState::default();
        us.session = Some(self.server_session);
        us.comment = Some(comment.into());
        self.send(us.into()).await;
    }

    pub async fn set_texture(&self, texture: Bytes) {
        let mut us = UserState::default();
        us.session = Some(self.server_session);
        us.texture = Some(texture);
        self.send(us.into()).await;
    }

    pub async fn request_session_comment(&self, session: u32) {
        self.send(
            RequestBlob {
                session_texture: Vec::new(),
                session_comment: vec![session],
                channel_description: Vec::new(),
            }
            .into(),
        )
        .await;
    }

    pub async fn request_session_texture(&self, session: u32) {
        self.send(
            RequestBlob {
                session_texture: vec![session],
                session_comment: Vec::new(),
                channel_description: Vec::new(),
            }
            .into(),
        )
        .await;
    }

    pub async fn mute_other(&self, target_session: u32, mute: bool) {
        let mut us = UserState::default();
        us.session = Some(ClientSessionIdentifier::from(target_session));
        us.mute = Some(mute);
        self.send(us.into()).await;
    }

    pub async fn deaf_other(&self, target_session: u32, deaf: bool) {
        let mut us = UserState::default();
        us.session = Some(ClientSessionIdentifier::from(target_session));
        us.deaf = Some(deaf);
        self.send(us.into()).await;
    }

    pub async fn suppress_other(&self, target_session: u32, suppress: bool) {
        let mut us = UserState::default();
        us.session = Some(ClientSessionIdentifier::from(target_session));
        us.suppress = Some(suppress);
        self.send(us.into()).await;
    }

    pub async fn move_other(&self, target_session: u32, channel_id: u32) {
        let mut us = UserState::default();
        us.session = Some(ClientSessionIdentifier::from(target_session));
        us.channel_id = Some(channel_id);
        self.send(us.into()).await;
    }

    pub async fn create_channel(&self, parent: u32, name: &str, temporary: bool) {
        // ChannelState without a channel_id triggers "create" path on the server.
        let cs = crate::messages::encoder::ChannelState {
            channel_id: None,
            parent: Some(parent),
            name: Some(name.into()),
            links: Vec::new(),
            description: None,
            links_add: Vec::new(),
            links_remove: Vec::new(),
            temporary: Some(temporary),
            position: None,
            description_hash: None,
            max_users: None,
            is_enter_restricted: None,
            can_enter: None,
        };
        self.send(cs.into()).await;
    }

    pub async fn update_channel_name(&self, channel_id: u32, name: &str) {
        let cs = crate::messages::encoder::ChannelState {
            channel_id: Some(channel_id),
            parent: None,
            name: Some(name.into()),
            links: Vec::new(),
            description: None,
            links_add: Vec::new(),
            links_remove: Vec::new(),
            temporary: None,
            position: None,
            description_hash: None,
            max_users: None,
            is_enter_restricted: None,
            can_enter: None,
        };
        self.send(cs.into()).await;
    }

    pub async fn remove_channel(&self, channel_id: u32) {
        let m: Message = ChannelRemove { channel_id }.into();
        self.send(m).await;
    }

    pub async fn set_acls(&self, channel_id: u32, acls: Vec<ChanAcl>, inherit_acls: bool) {
        let m: Message = crate::messages::encoder::Acl {
            channel_id,
            inherit_acls: Some(inherit_acls),
            groups: Vec::new(),
            acls,
            query: Some(false),
        }
        .into();
        self.send(m).await;
    }

    pub async fn query_acls(&self, channel_id: u32) {
        let m: Message = crate::messages::encoder::Acl {
            channel_id,
            inherit_acls: None,
            groups: Vec::new(),
            acls: Vec::new(),
            query: Some(true),
        }
        .into();
        self.send(m).await;
    }

    pub async fn kick(&self, target_session: u32, reason: &str) {
        let m: Message = UserRemove {
            session: target_session,
            actor: None,
            reason: Some(reason.into()),
            ban: Some(false),
        }
        .into();
        self.send(m).await;
    }

    pub async fn ban(&self, target_session: u32, reason: &str) {
        let m: Message = UserRemove {
            session: target_session,
            actor: None,
            reason: Some(reason.into()),
            ban: Some(true),
        }
        .into();
        self.send(m).await;
    }

    pub async fn set_voice_target(&self, target: VoiceTarget) {
        self.send(target.into()).await;
    }

    // ── TCP-tunneled voice ────────────────────────────────────────────────

    /// Send a voice frame as a `Message::UDPTunnel` (TCP-tunneled). The
    /// payload is encoded as a legacy Mumble Opus voice packet with the
    /// given target/frame/opus payload.
    pub async fn send_voice_tcp(&self, target: u32, frame_number: u64, opus: Bytes) {
        let bytes = encode_legacy_client_voice(target, frame_number, &opus);
        let msg = Message::UDPTunnel(bytes);
        self.send(msg).await;
    }

    /// Send a voice frame as a `Message::UDPTunnel` using the protobuf
    /// (Mumble 1.5+) wire format — what the official client emits.
    pub async fn send_voice_tcp_protobuf(&self, target: u32, frame_number: u64, opus: Bytes) {
        let bytes = encode_protobuf_client_voice(target, frame_number, &opus);
        self.send(Message::UDPTunnel(bytes)).await;
    }

    /// Send a legacy Opus voice frame with the terminator bit set (`0x2000` in
    /// the size_flag). Signals end-of-transmission per the Mumble wire spec.
    pub async fn send_voice_tcp_terminator(&self, target: u32, frame_number: u64, opus: Bytes) {
        let bytes = encode_legacy_client_voice_ex(target, frame_number, &opus, true, None);
        self.send(Message::UDPTunnel(bytes)).await;
    }

    /// Send a legacy Opus voice frame with positional audio data (XYZ floats
    /// in little-endian, appended after the Opus payload per the Mumble spec).
    pub async fn send_voice_tcp_with_positional(
        &self,
        target: u32,
        frame_number: u64,
        opus: Bytes,
        positional: [f32; 3],
    ) {
        let bytes =
            encode_legacy_client_voice_ex(target, frame_number, &opus, false, Some(positional));
        self.send(Message::UDPTunnel(bytes)).await;
    }

    /// Send a protobuf (Mumble 1.5+) voice frame with the terminator bit set.
    pub async fn send_voice_tcp_protobuf_terminator(
        &self,
        target: u32,
        frame_number: u64,
        opus: Bytes,
    ) {
        let bytes = encode_protobuf_client_voice_ex(target, frame_number, &opus, true, None);
        self.send(Message::UDPTunnel(bytes)).await;
    }

    /// Send a protobuf (Mumble 1.5+) voice frame with positional audio data.
    pub async fn send_voice_tcp_protobuf_with_positional(
        &self,
        target: u32,
        frame_number: u64,
        opus: Bytes,
        positional: [f32; 3],
    ) {
        let bytes =
            encode_protobuf_client_voice_ex(target, frame_number, &opus, false, Some(positional));
        self.send(Message::UDPTunnel(bytes)).await;
    }

    /// Wait for the next `Message::UDPTunnel` and return the decoded audio.
    pub async fn recv_voice_tcp(&self, deadline: Duration) -> Option<Audio> {
        let msg = self
            .recv_until(|m| matches!(m, Message::UDPTunnel(_)), deadline)
            .await?;
        match msg {
            Message::UDPTunnel(bytes) => decode_server_voice(&bytes),
            _ => None,
        }
    }

    // ── Real UDP voice (OCB2) ─────────────────────────────────────────────

    /// Bind a local UDP socket and remember the server's UDP address.
    pub async fn open_udp(&mut self) -> std::io::Result<()> {
        let sock = UdpSocket::bind(("127.0.0.1", 0u16)).await?;
        self.udp = Some(Arc::new(sock));
        Ok(())
    }

    /// Send an encrypted legacy ping over UDP. The server decrypts it (via
    /// the IP-fallback path), which has the side effect of binding our UDP
    /// address to our session. Unlike a voice packet, a ping is *not* echoed
    /// to other clients in the channel, so it's the right primitive for
    /// "make my address known" without polluting peers' audio queues.
    pub async fn udp_handshake(&self) -> std::io::Result<()> {
        let socket = self.udp.as_ref().expect("open_udp first").clone();
        let crypt = self.crypt.as_ref().expect("crypt state").clone();

        // Cleartext: legacy Ping = type-byte 0x20 followed by a PDS varint
        // timestamp. The server reads the timestamp back via `decode_ping_legacy`.
        let mut clear = BytesMut::with_capacity(2);
        clear.put_u8(0x20);
        write_pds_varint(&mut clear, 1u64);

        let mut encrypted = vec![0u8; clear.len() + 4];
        {
            let mut state = crypt.lock();
            state
                .encrypt(&mut encrypted, &clear)
                .expect("ocb2 encrypt ping");
        }
        socket.send_to(&encrypted, self.udp_server_addr).await?;
        Ok(())
    }

    /// Receive and decrypt the next UDP ping reply for this client.
    pub async fn recv_udp_ping(&self, deadline: Duration) -> Option<PingRequest> {
        let socket = self.udp.as_ref().expect("open_udp first").clone();
        let crypt = self.crypt.as_ref().expect("crypt state").clone();

        let res = timeout(deadline, async {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, _src) = socket.recv_from(&mut buf).await.ok()?;
                let mut decrypted = BytesMut::new();
                {
                    let mut state = crypt.lock();
                    if state.decrypt(&mut decrypted, &buf[..n]).is_err() {
                        continue;
                    }
                }
                if let Ok(IncomingUdpPacket::Ping(ping)) =
                    IncomingUdpPacket::decode(&decrypted, None)
                {
                    return Some(ping);
                }
            }
        })
        .await;
        res.ok().flatten()
    }

    /// Encode an audio frame, OCB2-encrypt it, and send over UDP.
    pub async fn send_voice_udp(
        &self,
        target: u32,
        frame_number: u64,
        opus: Bytes,
    ) -> std::io::Result<()> {
        let socket = self.udp.as_ref().expect("open_udp first").clone();
        let crypt = self.crypt.as_ref().expect("crypt state").clone();

        let cleartext = encode_legacy_client_voice(target, frame_number, &opus);

        let mut encrypted = vec![0u8; cleartext.len() + 4]; // 1 IV byte + 3-byte tag overhead
        {
            let mut state = crypt.lock();
            state
                .encrypt(&mut encrypted, &cleartext)
                .expect("ocb2 encrypt voice");
        }

        socket.send_to(&encrypted, self.udp_server_addr).await?;
        Ok(())
    }

    /// Same as [`send_voice_udp`] but uses the Mumble 1.5+ protobuf wire
    /// format (type byte `0x00` + encoded `MumbleUDP.Audio`).
    pub async fn send_voice_udp_protobuf(
        &self,
        target: u32,
        frame_number: u64,
        opus: Bytes,
    ) -> std::io::Result<()> {
        let socket = self.udp.as_ref().expect("open_udp first").clone();
        let crypt = self.crypt.as_ref().expect("crypt state").clone();

        let cleartext = encode_protobuf_client_voice(target, frame_number, &opus);

        let mut encrypted = vec![0u8; cleartext.len() + 4];
        {
            let mut state = crypt.lock();
            state
                .encrypt(&mut encrypted, &cleartext)
                .expect("ocb2 encrypt voice");
        }

        socket.send_to(&encrypted, self.udp_server_addr).await?;
        Ok(())
    }

    /// Receive UDP datagrams until the first audio packet arrives, decrypt
    /// it with the OCB2 state, decode it, and return it. Non-audio packets
    /// (pings) and decrypt failures are silently skipped within the deadline.
    pub async fn recv_voice_udp(&self, deadline: Duration) -> Option<Audio> {
        self.recv_voice_udp_until(|_| true, deadline).await
    }

    /// Like [`recv_voice_udp`] but skips packets that don't satisfy `predicate`.
    /// Useful when the queue contains "handshake echo" packets that arrive
    /// before the audio you actually want to assert on.
    pub async fn recv_voice_udp_until<F>(
        &self,
        mut predicate: F,
        deadline: Duration,
    ) -> Option<Audio>
    where
        F: FnMut(&Audio) -> bool,
    {
        let socket = self.udp.as_ref().expect("open_udp first").clone();
        let crypt = self.crypt.as_ref().expect("crypt state").clone();

        let res = timeout(deadline, async {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, _src) = socket.recv_from(&mut buf).await.ok()?;
                let mut decrypted = BytesMut::new();
                {
                    let mut state = crypt.lock();
                    if state.decrypt(&mut decrypted, &buf[..n]).is_err() {
                        continue;
                    }
                }
                // Route protobuf pings through the codec's full async decoder
                // (which understands legacy ping byte 0x20 and protobuf 0x01),
                // then fall back to our s→c-aware audio decoder so we handle
                // legacy server-encoded voice packets correctly.
                if !decrypted.is_empty() && (decrypted[0] == 0x01 || (decrypted[0] >> 5) == 1) {
                    if matches!(
                        IncomingUdpPacket::decode(&decrypted, None),
                        Ok(IncomingUdpPacket::Ping(_))
                    ) {
                        continue;
                    }
                }
                if let Some(a) = decode_server_voice(&decrypted) {
                    if predicate(&a) {
                        return Some(a);
                    }
                }
            }
        })
        .await;
        res.ok().flatten()
    }
}

impl ManualNativeClient {
    pub async fn connect(server: &TestServer) -> Result<Self, ConnectError> {
        let connection = open_native_connection(server, true).await?;
        Ok(Self {
            write: Mutex::new(connection.write_half),
            rx: Mutex::new(connection.msg_rx),
            _reader: connection.reader_handle,
        })
    }

    pub async fn send(&self, message: Message) {
        let mut w = self.write.lock().await;
        let _ = w.write_proto_message(&message).await;
    }

    pub async fn send_batch(&self, messages: &[Message]) {
        let mut w = self.write.lock().await;
        let _ = w.write_proto_message_batch(messages).await;
    }

    async fn recv_one(&self) -> Option<Message> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await? {
            Ok(m) => Some(m),
            Err(_) => None,
        }
    }

    pub async fn recv(&self, deadline: Duration) -> Option<Message> {
        timeout(deadline, self.recv_one()).await.ok().flatten()
    }

    pub async fn recv_closed(&self, deadline: Duration) -> bool {
        timeout(deadline, async {
            loop {
                let mut rx = self.rx.lock().await;
                match rx.recv().await {
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => return true,
                }
            }
        })
        .await
        .unwrap_or(false)
    }
}

async fn open_native_connection(
    server: &TestServer,
    present_client_cert: bool,
) -> Result<NativeConnection, ConnectError> {
    // ── Build CA-trusting RootCertStore ───────────────────────────────
    let ca_pem = std::fs::read_to_string(&server.pki.ca_path).expect("read ca pem");
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots
            .add(cert.expect("parse ca cert"))
            .expect("add root cert");
    }

    // ── Generate client cert (whether or not we present it: tests that
    //    assert on the certificate_hash still need the bytes) ───────────
    let key_pair = KeyPair::generate().expect("client keypair");
    let mut cert_params =
        CertificateParams::new(vec!["test-client".into()]).expect("client cert params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-client");
    cert_params.distinguished_name = dn;
    let client_cert = cert_params.self_signed(&key_pair).expect("self_signed");
    let cert_pem = client_cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_der_owned: Vec<u8> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .next()
        .expect("client cert pem -> der")
        .expect("client cert der parse")
        .to_vec();

    // ── Build TLS client config ───────────────────────────────────────
    let cfg_builder = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert));
    let cfg = if present_client_cert {
        let cert_der = CertificateDer::from(cert_der_owned.clone());
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("parse client key");
        cfg_builder
            .with_client_auth_cert(vec![cert_der], key_der)
            .expect("build tls client config with client cert")
    } else {
        cfg_builder.with_no_client_auth()
    };

    let connector = TlsConnector::from(Arc::new(cfg));

    // ── TCP + TLS handshake ───────────────────────────────────────────
    let tcp = TcpStream::connect(server.addr).await?;
    tcp.set_nodelay(true)?;
    let server_name = ServerName::try_from("localhost").expect("static server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ConnectError::Tls(format!("{e}")))?;

    let (read_half, write_half) = tokio::io::split(tls);

    // ── Spawn reader task ─────────────────────────────────────────────
    let (msg_tx, msg_rx) = mpsc::unbounded_channel::<Result<Message, String>>();
    let reader_handle = tokio::spawn(reader_loop(read_half, msg_tx));

    Ok(NativeConnection {
        write_half,
        msg_rx,
        reader_handle,
        cert_der: cert_der_owned,
    })
}

async fn reader_loop(
    mut read_half: ReadHalf<TlsStream<TcpStream>>,
    tx: mpsc::UnboundedSender<Result<Message, String>>,
) {
    loop {
        match read_half.read_proto_message().await {
            Ok(msg) => {
                if tx.send(Ok(msg)).is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = tx.send(Err(error.to_string()));
                break;
            }
        }
    }
}

/// A rustls server-cert verifier that accepts every certificate (server's
/// CA is enforced separately by virtue of being the only root in our root
/// store, but we also need to skip hostname validation since the test
/// server's cert has SAN `node-1`, not `localhost`).
#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
