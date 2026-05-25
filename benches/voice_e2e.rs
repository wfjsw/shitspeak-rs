use std::collections::HashMap;
use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{BufMut as _, Bytes, BytesMut};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use parking_lot::Mutex as PMutex;
use prost::Message as _;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
use rustls::{ClientConfig, RootCertStore};
use shitspeak_rs::api::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
};
use shitspeak_rs::client::client_session_identifier::ClientSessionIdentifier;
use shitspeak_rs::client::crypt::CryptState;
use shitspeak_rs::config::{Config, S2sConfig, UdpPingUserCountScope};
use shitspeak_rs::constants::{APP_PROTO_VER, PROTOBUF_INTRODUCED_VERSION};
use shitspeak_rs::messages::encoder::{
    Audio as AudioWire, AudioHeader, AudioTarget, Authenticate, ClientType, Version,
};
use shitspeak_rs::messages::{Message, ReadMessageExt, WriteMessageExt};
use shitspeak_rs::protocol_version::ProtocolVersion;
use shitspeak_rs::server::Server;
use shitspeak_rs::voice::codec::{
    Audio, AudioPayload, IncomingUdpPacket, OpusPayload, PacketFormat,
};
use tempfile::TempDir;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};

const SAMPLE_OPUS: &[u8] = &[
    0x4f, 0x70, 0x75, 0x73, 0x45, 0x32, 0x45, 0x2d, 0x62, 0x65, 0x6e, 0x63, 0x68, 0x2d, 0x31, 0x37,
    0x30, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
];
const VOICE_DEADLINE: Duration = Duration::from_secs(2);
const METRIC_SAMPLES: usize = 128;

#[derive(Debug, Clone, Copy)]
struct VoiceCase {
    name: &'static str,
    server_protocol_version: ProtocolVersion,
    recipient_protocol_version: ProtocolVersion,
    expected_format: PacketFormat,
}

#[derive(Debug)]
struct VoiceSample {
    delay: Duration,
    wire_bytes: usize,
    payload_bytes: usize,
    receive_at: Instant,
}

#[derive(Debug)]
struct VoiceMetrics {
    count: usize,
    p50_delay: Duration,
    p95_delay: Duration,
    p99_delay: Duration,
    mean_delay: Duration,
    max_delay: Duration,
    mean_jitter: Duration,
    max_jitter: Duration,
    payload_kbps: f64,
    wire_kbps: f64,
    mean_wire_bytes: usize,
}

impl VoiceMetrics {
    fn from_samples(samples: &[VoiceSample]) -> Self {
        assert!(!samples.is_empty(), "metrics need at least one sample");

        let mut delays = samples.iter().map(|s| s.delay).collect::<Vec<_>>();
        delays.sort_unstable();

        let total_delay = delays.iter().copied().sum::<Duration>();
        let total_payload_bytes = samples.iter().map(|s| s.payload_bytes).sum::<usize>();
        let total_wire_bytes = samples.iter().map(|s| s.wire_bytes).sum::<usize>();
        let elapsed = samples
            .last()
            .expect("last sample")
            .receive_at
            .duration_since(samples.first().expect("first sample").receive_at)
            .max(Duration::from_nanos(1));

        let mut jitters = samples
            .windows(2)
            .map(|pair| duration_abs_diff(pair[1].delay, pair[0].delay))
            .collect::<Vec<_>>();
        jitters.sort_unstable();
        let total_jitter = jitters.iter().copied().sum::<Duration>();

        Self {
            count: samples.len(),
            p50_delay: percentile(&delays, 50),
            p95_delay: percentile(&delays, 95),
            p99_delay: percentile(&delays, 99),
            mean_delay: total_delay / samples.len() as u32,
            max_delay: *delays.last().expect("max delay"),
            mean_jitter: if jitters.is_empty() {
                Duration::ZERO
            } else {
                total_jitter / jitters.len() as u32
            },
            max_jitter: jitters.last().copied().unwrap_or(Duration::ZERO),
            payload_kbps: kbps(total_payload_bytes, elapsed),
            wire_kbps: kbps(total_wire_bytes, elapsed),
            mean_wire_bytes: total_wire_bytes / samples.len(),
        }
    }

    fn mean_wire_bytes(&self) -> usize {
        self.mean_wire_bytes
    }

    fn report(&self, transport: &str, case: VoiceCase) {
        println!(
            "voice_e2e_metrics transport={transport} case={} samples={} format={:?} \
             delay_mean_us={} delay_p50_us={} delay_p95_us={} delay_p99_us={} delay_max_us={} \
             jitter_mean_us={} jitter_max_us={} payload_kbps={:.2} wire_kbps={:.2} mean_wire_bytes={}",
            case.name,
            self.count,
            case.expected_format,
            self.mean_delay.as_micros(),
            self.p50_delay.as_micros(),
            self.p95_delay.as_micros(),
            self.p99_delay.as_micros(),
            self.max_delay.as_micros(),
            self.mean_jitter.as_micros(),
            self.max_jitter.as_micros(),
            self.payload_kbps,
            self.wire_kbps,
            self.mean_wire_bytes,
        );
    }
}

struct BenchPki {
    _dir: TempDir,
    cert_path: String,
    key_path: String,
    ca_path: String,
}

struct BenchServer {
    _server: Arc<Box<Server>>,
    addr: SocketAddr,
    udp_addr: SocketAddr,
    authenticator: Arc<BenchAuthenticator>,
    _run_handle: JoinHandle<()>,
    _pki: BenchPki,
}

#[derive(Clone)]
struct BenchUser {
    user_id: Option<u32>,
    groups: Vec<String>,
}

#[derive(Default)]
struct BenchAuthenticator {
    users: StdMutex<HashMap<String, BenchUser>>,
}

struct AuthenticatorAdapter(Arc<BenchAuthenticator>);

#[async_trait]
impl Authenticator for AuthenticatorAdapter {
    async fn authenticate(
        &self,
        username: &str,
        _password: Option<&str>,
        _auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        let user = self
            .0
            .users
            .lock()
            .expect("auth users lock")
            .get(username)
            .cloned()
            .ok_or(AuthenticationRejection::NoSuchUser)?;
        Ok(AuthenticateResult {
            user_id: user.user_id,
            display_name: Some(username.to_owned()),
            groups: user.groups,
            virtual_server_id: None,
            language: shitspeak_rs::localization::Language::default(),
            texture_url: None,
            comment_url: None,
        })
    }
}

impl BenchAuthenticator {
    fn register_user(&self, name: &str, user_id: Option<u32>, groups: Vec<String>) {
        self.users
            .lock()
            .expect("auth users lock")
            .insert(name.to_owned(), BenchUser { user_id, groups });
    }
}

struct BenchClient {
    server_session: ClientSessionIdentifier,
    write: Mutex<WriteHalf<TlsStream<TcpStream>>>,
    rx: Mutex<mpsc::UnboundedReceiver<Result<Message, ()>>>,
    udp: Option<Arc<UdpSocket>>,
    udp_server_addr: SocketAddr,
    crypt: Option<Arc<PMutex<CryptState>>>,
    _reader: JoinHandle<()>,
}

fn install_provider_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn mint_pki() -> BenchPki {
    let dir = TempDir::new().expect("temp pki dir");
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(vec!["voice-e2e-ca".into()]).expect("ca params");
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "voice-e2e-ca");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let node_key = KeyPair::generate().expect("node key");
    let mut node_params = CertificateParams::new(vec!["localhost".into()]).expect("node params");
    let mut node_dn = DistinguishedName::new();
    node_dn.push(DnType::CommonName, "localhost");
    node_params.distinguished_name = node_dn;
    let node_cert = node_params
        .signed_by(&node_key, &ca_cert, &ca_key)
        .expect("node cert");

    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&ca_path, ca_cert.pem()).expect("write ca");
    std::fs::write(&cert_path, node_cert.pem()).expect("write cert");
    std::fs::write(&key_path, node_key.serialize_pem()).expect("write key");

    BenchPki {
        _dir: dir,
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        ca_path: ca_path.to_string_lossy().into_owned(),
    }
}

fn bench_config(pki: &BenchPki, server_protocol_version: ProtocolVersion) -> Config {
    Config {
        node_id: 1,
        listen: "127.0.0.1:0".into(),
        server_entrypoints: Vec::new(),
        register_name: "voice-e2e-bench".into(),
        register_password: None,
        register_url: None,
        register_hostname: None,
        register_location: None,
        cert_path: pki.cert_path.clone(),
        key_path: pki.key_path.clone(),
        send_version: false,
        send_build_info: false,
        send_os_info: false,
        server_protocol_version,
        allowed_proxies: Vec::new(),
        min_client_version: 0,
        max_users: 128,
        authenticator_wasm_path: None,
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
        udp_voice_enabled: true,
        udp_ping_enabled: true,
        udp_ping_user_count_scope: UdpPingUserCountScope::Cluster,
        udp_channel_size: 2_048,
        client_idle_timeout_secs: 30,
        pending_delete_timeout_ms: 5_000,
        required_groups: Vec::new(),
        send_permission_info: false,
        hide_users_without_traverse: false,
        s2s: S2sConfig::default(),
        web: shitspeak_rs::config::WebConfig::default(),
    }
}

async fn spawn_bench_server(server_protocol_version: ProtocolVersion) -> BenchServer {
    install_provider_once();
    let pki = mint_pki();
    let authenticator = Arc::new(BenchAuthenticator::default());
    let adapter = AuthenticatorAdapter(Arc::clone(&authenticator));
    let server = Server::new(bench_config(&pki, server_protocol_version), adapter)
        .await
        .expect("Server::new");
    let addr = server.local_addr().expect("tcp addr");
    let udp_addr = server.local_udp_addr().expect("udp addr");
    let run_handle = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let _ = server.run().await;
        }
    });

    BenchServer {
        _server: server,
        addr,
        udp_addr,
        authenticator,
        _run_handle: run_handle,
        _pki: pki,
    }
}

impl Drop for BenchServer {
    fn drop(&mut self) {
        self._server.shutdown();
    }
}

async fn reader_loop(
    mut read_half: ReadHalf<TlsStream<TcpStream>>,
    tx: mpsc::UnboundedSender<Result<Message, ()>>,
) {
    loop {
        match read_half.read_proto_message().await {
            Ok(msg) => {
                if tx.send(Ok(msg)).is_err() {
                    break;
                }
            }
            Err(_) => {
                let _ = tx.send(Err(()));
                break;
            }
        }
    }
}

async fn connect_client(
    server: &BenchServer,
    username: &str,
    declared_version: ProtocolVersion,
) -> BenchClient {
    let ca_pem = std::fs::read_to_string(&server._pki.ca_path).expect("read ca");
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(cert.expect("ca der")).expect("add ca");
    }
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(server.addr).await.expect("tcp connect");
    let tls = connector
        .connect(ServerName::try_from("localhost").expect("server name"), tcp)
        .await
        .expect("tls connect");
    let (read_half, write_half) = tokio::io::split(tls);
    let (tx, rx) = mpsc::unbounded_channel();
    let reader = tokio::spawn(reader_loop(read_half, tx));

    let client = BenchClient {
        server_session: ClientSessionIdentifier::from(0u32),
        write: Mutex::new(write_half),
        rx: Mutex::new(rx),
        udp: None,
        udp_server_addr: server.udp_addr,
        crypt: None,
        _reader: reader,
    };

    let version: Message = Version {
        version: Some(declared_version),
        release: Some("voice-e2e-bench".into()),
        os: Some("bench".into()),
        os_version: Some("bench".into()),
    }
    .into();
    client.send(version).await;

    let auth: Message = Authenticate {
        username: Some(username.into()),
        password: None,
        tokens: Vec::new(),
        celt_versions: Vec::new(),
        opus: Some(true),
        client_type: ClientType::Regular,
    }
    .into();
    client.send(auth).await;

    let mut client = client;
    timeout(Duration::from_secs(5), async {
        loop {
            match client.recv_one().await.expect("message before sync") {
                Message::CryptSetup(cs) => {
                    let key = cs.key.unwrap_or_default();
                    let client_nonce = cs.client_nonce.unwrap_or_default();
                    let server_nonce = cs.server_nonce.unwrap_or_default();
                    if !key.is_empty() && !client_nonce.is_empty() && !server_nonce.is_empty() {
                        client.crypt = Some(Arc::new(PMutex::new(
                            CryptState::from_key("OCB2-AES128", &key, &client_nonce, &server_nonce)
                                .expect("crypt state"),
                        )));
                    }
                }
                Message::ServerSync(sync) => {
                    client.server_session =
                        ClientSessionIdentifier::from(sync.session.unwrap_or(0));
                    break;
                }
                Message::Reject(reject) => panic!("auth rejected: {reject:?}"),
                _ => {}
            }
        }
    })
    .await
    .expect("server sync");

    client
}

impl BenchClient {
    async fn send(&self, message: Message) {
        self.write
            .lock()
            .await
            .write_proto_message(&message)
            .await
            .expect("write message");
    }

    async fn recv_one(&self) -> Option<Message> {
        match self.rx.lock().await.recv().await {
            Some(Ok(message)) => Some(message),
            _ => None,
        }
    }

    async fn recv_until<F>(&self, mut predicate: F, deadline: Duration) -> Option<Message>
    where
        F: FnMut(&Message) -> bool,
    {
        timeout(deadline, async {
            loop {
                let msg = self.recv_one().await?;
                if predicate(&msg) {
                    return Some(msg);
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    async fn send_voice_tcp(&self, frame: u64, opus: Bytes, format: PacketFormat) {
        self.send(Message::UDPTunnel(encode_client_voice(
            0, frame, &opus, format,
        )))
        .await;
    }

    async fn send_voice_udp(&self, frame: u64, opus: Bytes, format: PacketFormat) {
        let socket = self.udp.as_ref().expect("open_udp first");
        let clear = encode_client_voice(0, frame, &opus, format);
        let encrypted = self.encrypt_udp(&clear);
        socket
            .send_to(&encrypted, self.udp_server_addr)
            .await
            .expect("udp voice send");
    }

    async fn recv_voice_tcp_measured(&self) -> (Audio, usize) {
        let msg = self
            .recv_until(|m| matches!(m, Message::UDPTunnel(_)), VOICE_DEADLINE)
            .await
            .expect("tcp voice receive");
        match msg {
            Message::UDPTunnel(bytes) => {
                let wire_bytes = bytes.len() + 6; // Mumble TCP message type + length prefix.
                (
                    decode_server_voice(&bytes).expect("decode tcp voice"),
                    wire_bytes,
                )
            }
            _ => unreachable!(),
        }
    }

    async fn recv_voice_udp_measured(&self) -> (Audio, usize) {
        let socket = self.udp.as_ref().expect("open_udp first").clone();
        let crypt = self.crypt.as_ref().expect("crypt state").clone();
        timeout(VOICE_DEADLINE, async {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, _) = socket.recv_from(&mut buf).await.expect("udp receive");
                let mut decrypted = BytesMut::new();
                {
                    let mut state = crypt.lock();
                    if state.decrypt(&mut decrypted, &buf[..n]).is_err() {
                        continue;
                    }
                }
                if !decrypted.is_empty()
                    && (decrypted[0] == 0x01 || (decrypted[0] >> 5) == 1)
                    && matches!(
                        IncomingUdpPacket::decode(&decrypted, None),
                        Ok(IncomingUdpPacket::Ping(_))
                    )
                {
                    continue;
                }
                if let Some(audio) = decode_server_voice(&decrypted) {
                    return (audio, n);
                }
            }
        })
        .await
        .expect("udp voice receive")
    }

    async fn recv_voice_tcp(&self) -> Audio {
        let msg = self
            .recv_until(|m| matches!(m, Message::UDPTunnel(_)), VOICE_DEADLINE)
            .await
            .expect("tcp voice receive");
        match msg {
            Message::UDPTunnel(bytes) => decode_server_voice(&bytes).expect("decode tcp voice"),
            _ => unreachable!(),
        }
    }

    async fn recv_voice_udp(&self) -> Audio {
        let socket = self.udp.as_ref().expect("open_udp first").clone();
        let crypt = self.crypt.as_ref().expect("crypt state").clone();
        timeout(VOICE_DEADLINE, async {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, _) = socket.recv_from(&mut buf).await.expect("udp receive");
                let mut decrypted = BytesMut::new();
                {
                    let mut state = crypt.lock();
                    if state.decrypt(&mut decrypted, &buf[..n]).is_err() {
                        continue;
                    }
                }
                if !decrypted.is_empty()
                    && (decrypted[0] == 0x01 || (decrypted[0] >> 5) == 1)
                    && matches!(
                        IncomingUdpPacket::decode(&decrypted, None),
                        Ok(IncomingUdpPacket::Ping(_))
                    )
                {
                    continue;
                }
                if let Some(audio) = decode_server_voice(&decrypted) {
                    return audio;
                }
            }
        })
        .await
        .expect("udp voice receive")
    }

    async fn open_udp(&mut self) {
        self.udp = Some(Arc::new(
            UdpSocket::bind(("127.0.0.1", 0u16))
                .await
                .expect("udp bind"),
        ));
    }

    async fn udp_handshake(&self) {
        let mut clear = BytesMut::with_capacity(2);
        clear.put_u8(0x20);
        write_pds_varint(&mut clear, 1u64);
        let encrypted = self.encrypt_udp(&clear);
        self.udp
            .as_ref()
            .expect("open_udp first")
            .send_to(&encrypted, self.udp_server_addr)
            .await
            .expect("udp handshake send");
    }

    fn encrypt_udp(&self, clear: &[u8]) -> Vec<u8> {
        let crypt = self.crypt.as_ref().expect("crypt state");
        let mut state = crypt.lock();
        let mut encrypted = vec![0u8; clear.len() + state.overhead()];
        state.encrypt(&mut encrypted, clear).expect("udp encrypt");
        encrypted
    }
}

fn setup_tcp(rt: &tokio::runtime::Runtime, case: VoiceCase) -> E2ePair {
    rt.block_on(async {
        let server = spawn_bench_server(case.server_protocol_version).await;
        server
            .authenticator
            .register_user("alice", Some(1), vec!["admin".into()]);
        server.authenticator.register_user("bob", Some(2), vec![]);
        let alice = connect_client(&server, "alice", PROTOBUF_INTRODUCED_VERSION).await;
        let bob = connect_client(&server, "bob", case.recipient_protocol_version).await;
        E2ePair {
            _server: server,
            alice,
            bob,
        }
    })
}

fn setup_udp(rt: &tokio::runtime::Runtime, case: VoiceCase) -> E2ePair {
    rt.block_on(async {
        let server = spawn_bench_server(case.server_protocol_version).await;
        server
            .authenticator
            .register_user("alice", Some(1), vec!["admin".into()]);
        server.authenticator.register_user("bob", Some(2), vec![]);
        let mut alice = connect_client(&server, "alice", PROTOBUF_INTRODUCED_VERSION).await;
        let mut bob = connect_client(&server, "bob", case.recipient_protocol_version).await;
        alice.open_udp().await;
        bob.open_udp().await;
        alice.udp_handshake().await;
        bob.udp_handshake().await;
        wait_for_udp_binding(&server, bob.server_session).await;
        wait_for_udp_binding(&server, alice.server_session).await;
        E2ePair {
            _server: server,
            alice,
            bob,
        }
    })
}

async fn wait_for_udp_binding(server: &BenchServer, session: ClientSessionIdentifier) {
    timeout(Duration::from_secs(2), async {
        loop {
            let bound = server
                ._server
                .get_clients()
                .get_client(session)
                .await
                .and_then(|client| client.get_udp_address())
                .is_some();
            if bound {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("UDP binding");
}

const VOICE_CASES: &[VoiceCase] = &[
    VoiceCase {
        name: "server_1_4_all_legacy",
        server_protocol_version: APP_PROTO_VER,
        recipient_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        expected_format: PacketFormat::Legacy,
    },
    VoiceCase {
        name: "server_1_5_client_1_4_legacy",
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        recipient_protocol_version: APP_PROTO_VER,
        expected_format: PacketFormat::Legacy,
    },
    VoiceCase {
        name: "server_1_5_client_1_5_protobuf",
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        recipient_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        expected_format: PacketFormat::Protobuf,
    },
];

fn payload_len(audio: &Audio) -> usize {
    audio.audio_payload.len()
}

fn percentile(sorted: &[Duration], percentile: usize) -> Duration {
    assert!(!sorted.is_empty(), "percentile needs at least one value");
    let index = ((sorted.len() - 1) * percentile) / 100;
    sorted[index]
}

fn duration_abs_diff(lhs: Duration, rhs: Duration) -> Duration {
    if lhs >= rhs { lhs - rhs } else { rhs - lhs }
}

fn kbps(bytes: usize, elapsed: Duration) -> f64 {
    (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1000.0
}

fn measure_tcp_e2e(
    rt: &tokio::runtime::Runtime,
    pair: &E2ePair,
    case: VoiceCase,
    sample_count: usize,
) -> VoiceMetrics {
    let mut frame = 10_000u64;
    let mut samples = Vec::with_capacity(sample_count);
    rt.block_on(async {
        for _ in 0..sample_count {
            frame += 1;
            let started = Instant::now();
            pair.alice
                .send_voice_tcp(frame, Bytes::from_static(SAMPLE_OPUS), case.expected_format)
                .await;
            let (audio, wire_bytes) = pair.bob.recv_voice_tcp_measured().await;
            let received = Instant::now();
            assert_eq!(audio.format, case.expected_format);
            samples.push(VoiceSample {
                delay: received.duration_since(started),
                wire_bytes,
                payload_bytes: payload_len(&audio),
                receive_at: received,
            });
        }
    });
    VoiceMetrics::from_samples(&samples)
}

fn measure_udp_e2e(
    rt: &tokio::runtime::Runtime,
    pair: &E2ePair,
    case: VoiceCase,
    sample_count: usize,
) -> VoiceMetrics {
    let mut frame = 20_000u64;
    let mut samples = Vec::with_capacity(sample_count);
    rt.block_on(async {
        for _ in 0..sample_count {
            frame += 1;
            let started = Instant::now();
            pair.alice
                .send_voice_udp(frame, Bytes::from_static(SAMPLE_OPUS), case.expected_format)
                .await;
            let (audio, wire_bytes) = pair.bob.recv_voice_udp_measured().await;
            let received = Instant::now();
            assert_eq!(audio.format, case.expected_format);
            samples.push(VoiceSample {
                delay: received.duration_since(started),
                wire_bytes,
                payload_bytes: payload_len(&audio),
                receive_at: received,
            });
        }
    });
    VoiceMetrics::from_samples(&samples)
}

struct E2ePair {
    _server: BenchServer,
    alice: BenchClient,
    bob: BenchClient,
}

fn bench_tcp_e2e(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .expect("runtime");
    let mut group = c.benchmark_group("voice_e2e/tcp_roundtrip");
    for &case in VOICE_CASES {
        let pair = setup_tcp(&rt, case);
        let metrics = measure_tcp_e2e(&rt, &pair, case, METRIC_SAMPLES);
        metrics.report("tcp", case);
        group.throughput(Throughput::Bytes(metrics.mean_wire_bytes().max(1) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(case.name), &case, |b, &case| {
            let mut frame = 1u64;
            b.iter(|| {
                frame += 1;
                let audio = rt.block_on(async {
                    pair.alice
                        .send_voice_tcp(
                            frame,
                            Bytes::from_static(SAMPLE_OPUS),
                            case.expected_format,
                        )
                        .await;
                    pair.bob.recv_voice_tcp().await
                });
                assert_eq!(audio.format, case.expected_format);
                black_box(audio);
            });
        });
    }
    group.finish();
}

fn bench_udp_e2e(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .expect("runtime");
    let mut group = c.benchmark_group("voice_e2e/udp_roundtrip");
    for &case in VOICE_CASES {
        let pair = setup_udp(&rt, case);
        let metrics = measure_udp_e2e(&rt, &pair, case, METRIC_SAMPLES);
        metrics.report("udp", case);
        group.throughput(Throughput::Bytes(metrics.mean_wire_bytes().max(1) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(case.name), &case, |b, &case| {
            let mut frame = 1u64;
            b.iter(|| {
                frame += 1;
                let audio = rt.block_on(async {
                    pair.alice
                        .send_voice_udp(
                            frame,
                            Bytes::from_static(SAMPLE_OPUS),
                            case.expected_format,
                        )
                        .await;
                    pair.bob.recv_voice_udp().await
                });
                assert_eq!(audio.format, case.expected_format);
                black_box(audio);
            });
        });
    }
    group.finish();
}

fn encode_legacy_client_voice(target: u32, frame_number: u64, opus: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + 4 + 4 + opus.len());
    buf.put_u8((0x04u8 << 5) | (target as u8 & 0x1f));
    write_pds_varint(&mut buf, frame_number);
    write_pds_varint(&mut buf, opus.len() as u64 & 0x1fff);
    buf.extend_from_slice(opus);
    buf.freeze()
}

fn encode_protobuf_client_voice(target: u32, frame_number: u64, opus: &[u8]) -> Bytes {
    let wire = AudioWire {
        header: Some(AudioHeader::Target(AudioTarget::from(target))),
        sender_session: 0,
        frame_number,
        opus_data: Bytes::copy_from_slice(opus),
        positional_data: vec![],
        volume_adjustment: 0.0,
        is_terminator: false,
    };
    let proto: shitspeak_rs::mumble_udp::Audio = wire.into();
    let mut buf = BytesMut::with_capacity(1 + proto.encoded_len());
    buf.put_u8(0x00);
    proto.encode(&mut buf).expect("encode protobuf audio");
    buf.freeze()
}

fn encode_client_voice(target: u32, frame_number: u64, opus: &[u8], format: PacketFormat) -> Bytes {
    match format {
        PacketFormat::Legacy => encode_legacy_client_voice(target, frame_number, opus),
        PacketFormat::Protobuf => encode_protobuf_client_voice(target, frame_number, opus),
    }
}

fn read_pds_varint(data: &[u8]) -> Option<(u64, usize)> {
    let c = *data.first()? as u64;
    if c & 0x80 == 0 {
        Some((c, 1))
    } else if c & 0x40 == 0 {
        Some(((c & 0x3f) << 8 | *data.get(1)? as u64, 2))
    } else if c & 0x20 == 0 {
        Some((
            (c & 0x1f) << 16 | (*data.get(1)? as u64) << 8 | *data.get(2)? as u64,
            3,
        ))
    } else if c & 0x10 == 0 {
        Some((
            (c & 0x0f) << 24
                | (*data.get(1)? as u64) << 16
                | (*data.get(2)? as u64) << 8
                | *data.get(3)? as u64,
            4,
        ))
    } else {
        None
    }
}

fn write_pds_varint(buf: &mut BytesMut, value: u64) {
    if value <= 0x7f {
        buf.put_u8(value as u8);
    } else if value <= 0x3fff {
        buf.put_u8(0x80 | (value >> 8) as u8);
        buf.put_u8((value & 0xff) as u8);
    } else if value <= 0x1f_ffff {
        buf.put_u8(0xc0 | (value >> 16) as u8);
        buf.put_u8(((value >> 8) & 0xff) as u8);
        buf.put_u8((value & 0xff) as u8);
    } else if value <= 0x0fff_ffff {
        buf.put_u8(0xe0 | (value >> 24) as u8);
        buf.put_u8(((value >> 16) & 0xff) as u8);
        buf.put_u8(((value >> 8) & 0xff) as u8);
        buf.put_u8((value & 0xff) as u8);
    } else {
        buf.put_u8(0xef);
        buf.put_u8(0xff);
        buf.put_u8(0xff);
        buf.put_u8(0xff);
    }
}

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

fn decode_legacy_server_voice(data: &[u8]) -> Option<Audio> {
    if data.len() < 2 {
        return None;
    }
    let header = data[0];
    if (header >> 5) != 4 {
        return None;
    }
    let target = AudioTarget::from((header & 0x1f) as u32);
    let mut pos = 1usize;
    let (sender_session, n) = read_pds_varint(&data[pos..])?;
    pos += n;
    let (frame_number, n) = read_pds_varint(&data[pos..])?;
    pos += n;
    let (size_flag, n) = read_pds_varint(&data[pos..])?;
    pos += n;
    let payload_size = (size_flag & 0x1fff) as usize;
    let is_terminator = (size_flag & 0x2000) != 0;
    if pos + payload_size > data.len() {
        return None;
    }
    let frame = Bytes::copy_from_slice(&data[pos..pos + payload_size]);
    Some(Audio {
        target,
        sender_session: Some(ClientSessionIdentifier::from(sender_session as u32)),
        frame_number,
        audio_payload: AudioPayload::Opus(OpusPayload {
            frame,
            is_terminator,
        }),
        positional_data: None,
        volume_adjustment: 1.0,
        format: PacketFormat::Legacy,
    })
}

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

criterion_group!(benches, bench_tcp_e2e, bench_udp_e2e);
criterion_main!(benches);
