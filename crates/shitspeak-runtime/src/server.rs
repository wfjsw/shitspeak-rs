use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use parking_lot::{Mutex, RwLock as ParkingRwLock};
use rand::RngExt;

use cidr::AnyIpCidr;
use prost::{EncodeError, Message as _};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use rustls::version::{TLS12, TLS13};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::Instrument;

use crate::api::{Authenticator, ReloadableAuthenticator};
use crate::blob_store::{ChannelBlobStore, SessionBlobStore};
use crate::channel_handler::{ChannelReplayError, ChannelTreeShadow, SessionChannelShadow};
use crate::channel_repository::{
    ChannelOp, ChannelOperation, ChannelRepoTuning, ChannelRepository, ChannelRootConfig,
};
use crate::client::{
    AsyncMessageHandlerExt, Client, ClientInstanceId, ClientOutboundMessage,
    client_session_identifier::ClientSessionIdentifier,
    state_log::{
        ClientGlobalStateDelta, ClientStateBroadcastPayload, ClientStateLogEntry,
        ClientStateOperation,
    },
    visibility::UserVisibilityState,
};
use crate::client_certificate_verifier::ClientCertificateVerifier;
use crate::errors::{
    HandleIncomingConnectionError, MessageHandlerError, ReadProtoMessageError,
    WriteProtoMessageError,
};
use crate::geoip::{GeoIpResolver, IpGeoMetadata};
use crate::messages::encoder::{TextMessage, Version};
use crate::messages::{Message, WriteMessageExt};
use crate::proxy_protocol::consume_proxy_protocol_connection_info;
use crate::user_channel_cache::UserChannelCache;
use crate::{
    client_repository::ClientRepository,
    codec_info::CodecInfo,
    config::{
        AuthenticatorConfig, CertificateHashProtection, Config, ServerEntrypointConfig,
        UdpPingUserCountScope,
    },
    constants::MTU,
    s2s::S2SManager,
    types::{DEFAULT_SERVER_ID, NodeIdentifier, default_server_id},
};

type ClientLogReceiver = tokio::sync::broadcast::Receiver<Arc<ClientStateBroadcastPayload>>;
type ChannelLogReceiver = tokio::sync::broadcast::Receiver<Arc<ChannelOperation>>;
type UdpPacket = (Bytes, std::net::SocketAddr, std::net::SocketAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelLogReceiveOutcome {
    Continue,
    Closed,
}

const CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT: usize = 64;
const ALPN_MUMBLE: &[u8] = b"mumble";
const DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS: usize = 128;
const DYNAMIC_ENTRYPOINT_MIN_PORT: u16 = 49152;
const DYNAMIC_ENTRYPOINT_MAX_PORT: u16 = 65535;
const MIN_AUTHENTICATE_TIMEOUT_MS: u64 = 1;
const AUTH_FINALIZATION_QUEUE_NOTICE_INTERVAL: Duration = Duration::from_secs(5);
const PRE_AUTH_DEFERRED_MESSAGE_LIMIT: usize = 32;

pub type ServerExtensionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), HandleIncomingConnectionError>> + Send + 'a>>;

#[derive(Clone, Debug)]
pub struct AlpnConnectionInfo {
    real_ip: std::net::IpAddr,
    client_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    server_id: String,
    tls_ja4: Option<String>,
    uses_proxy_protocol: bool,
}

impl AlpnConnectionInfo {
    fn new(
        real_ip: std::net::IpAddr,
        client_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        server_id: String,
        tls_ja4: Option<String>,
        uses_proxy_protocol: bool,
    ) -> Self {
        Self {
            real_ip,
            client_addr,
            local_addr,
            server_id,
            tls_ja4,
            uses_proxy_protocol,
        }
    }

    pub fn real_ip(&self) -> std::net::IpAddr {
        self.real_ip
    }

    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn tls_ja4(&self) -> Option<&str> {
        self.tls_ja4.as_deref()
    }

    pub fn uses_proxy_protocol(&self) -> bool {
        self.uses_proxy_protocol
    }
}

pub trait ServerExtension: Send + Sync + 'static {
    fn c2s_alpn_protocols(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn spawn_tasks(
        &self,
        _server: Arc<Box<Server>>,
        _shutdown: tokio::sync::watch::Receiver<()>,
        _tasks: &mut JoinSet<()>,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn handle_c2s_alpn_stream<'a>(
        &'a self,
        _server: Arc<Box<Server>>,
        _protocol: &'a [u8],
        _stream: TlsStream<TcpStream>,
        _info: AlpnConnectionInfo,
    ) -> Option<ServerExtensionFuture<'a>> {
        None
    }
}

#[derive(Clone, Default)]
pub struct ServerExtensions {
    extensions: Vec<Arc<dyn ServerExtension>>,
}

impl ServerExtensions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with<E>(mut self, extension: E) -> Self
    where
        E: ServerExtension,
    {
        self.push(extension);
        self
    }

    pub fn push<E>(&mut self, extension: E)
    where
        E: ServerExtension,
    {
        self.extensions.push(Arc::new(extension));
    }

    pub fn push_arc(&mut self, extension: Arc<dyn ServerExtension>) {
        self.extensions.push(extension);
    }

    fn c2s_alpn_protocols(&self) -> Vec<Vec<u8>> {
        self.extensions
            .iter()
            .flat_map(|extension| extension.c2s_alpn_protocols())
            .collect()
    }

    fn handles_c2s_alpn_protocol(&self, protocol: &[u8]) -> bool {
        self.extensions.iter().any(|extension| {
            extension
                .c2s_alpn_protocols()
                .iter()
                .any(|candidate| candidate.as_slice() == protocol)
        })
    }

    fn spawn_tasks(
        &self,
        server: Arc<Box<Server>>,
        shutdown: tokio::sync::watch::Receiver<()>,
        tasks: &mut JoinSet<()>,
    ) -> std::io::Result<()> {
        for extension in &self.extensions {
            extension.spawn_tasks(Arc::clone(&server), shutdown.clone(), tasks)?;
        }
        Ok(())
    }

    fn handle_c2s_alpn_stream<'a>(
        &'a self,
        server: Arc<Box<Server>>,
        protocol: &'a [u8],
        stream: TlsStream<TcpStream>,
        info: AlpnConnectionInfo,
    ) -> Option<ServerExtensionFuture<'a>> {
        self.extensions
            .iter()
            .find(|extension| {
                extension
                    .c2s_alpn_protocols()
                    .iter()
                    .any(|candidate| candidate.as_slice() == protocol)
            })
            .and_then(|extension| extension.handle_c2s_alpn_stream(server, protocol, stream, info))
    }
}

fn startup_file_error(
    config_key: &str,
    path: &str,
    action: &str,
    source: impl std::fmt::Display,
) -> Box<dyn std::error::Error> {
    std::io::Error::other(format!(
        "{action} failed for {config_key}={path:?}: {source}"
    ))
    .into()
}

fn first_socket_addr(address: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    address.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid listen address: {address}"),
        )
        .into()
    })
}

fn c2s_pfs_tls_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites.retain(c2s_cipher_suite_provides_pfs);
    provider
}

fn c2s_cipher_suite_provides_pfs(suite: &rustls::SupportedCipherSuite) -> bool {
    matches!(
        suite.suite(),
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
            | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            | rustls::CipherSuite::TLS13_AES_128_CCM_SHA256
            | rustls::CipherSuite::TLS13_AES_128_CCM_8_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
}

fn load_c2s_tls_config(
    config: &Config,
    extensions: &ServerExtensions,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let certificate = CertificateDer::pem_file_iter(&config.cert_path)
        .map_err(|e| startup_file_error("cert_path", &config.cert_path, "read TLS certificate", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            startup_file_error("cert_path", &config.cert_path, "parse TLS certificate", e)
        })?;
    let private_key = PrivateKeyDer::from_pem_file(&config.key_path)
        .map_err(|e| startup_file_error("key_path", &config.key_path, "read TLS private key", e))?;

    let client_cert_verifier = Arc::new(ClientCertificateVerifier::new());

    let mut tls_config =
        rustls::ServerConfig::builder_with_provider(Arc::new(c2s_pfs_tls_provider()))
            .with_protocol_versions(&[&TLS13, &TLS12])?
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(certificate, private_key)?;
    tls_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls_config.send_tls13_tickets = 0;
    tls_config
        .alpn_protocols
        .extend(extensions.c2s_alpn_protocols());
    tls_config.alpn_protocols.push(ALPN_MUMBLE.to_vec());

    Ok(tls_config)
}

fn load_c2s_tls_acceptor(
    config: &Config,
    extensions: &ServerExtensions,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let tls_config = load_c2s_tls_config(config, extensions)?;
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

fn validate_privacy_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.privacy.protect_certificate_hashes()
        && config
            .privacy
            .certificate_hash_secret()
            .map(str::trim)
            .filter(|secret| !secret.is_empty())
            .is_none()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "privacy.protect_certificate_hashes requires privacy.certificate_hash_secret when set to true, \"irreversible\", or \"reversible\"",
        )
        .into());
    }
    Ok(())
}

async fn bind_entrypoint_socket_pair(
    address: SocketAddr,
) -> Result<(tokio::net::TcpListener, Arc<tokio::net::UdpSocket>), Box<dyn std::error::Error>> {
    if address.port() != 0 {
        return bind_entrypoint_socket_pair_once(address).await;
    }

    let mut last_bind_error = None;
    for attempt in 1..=DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS {
        let candidate = dynamic_entrypoint_bind_candidate(address, attempt);
        let udp_socket = match tokio::net::UdpSocket::bind(candidate).await {
            Ok(socket) => socket,
            Err(err) if dynamic_bind_error_is_retryable(&err) => {
                tracing::debug!(
                    attempt,
                    attempts = DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS,
                    %candidate,
                    error = ?err,
                    "entrypoint UDP candidate is unavailable; retrying entrypoint bind"
                );
                last_bind_error = Some(err);
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        let bound_address = udp_socket.local_addr()?;
        match tokio::net::TcpListener::bind(bound_address).await {
            Ok(tcp_listener) => return Ok((tcp_listener, Arc::new(udp_socket))),
            Err(err) if dynamic_bind_error_is_retryable(&err) => {
                tracing::debug!(
                    attempt,
                    attempts = DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS,
                    %bound_address,
                    error = ?err,
                    "ephemeral UDP port's TCP address is unavailable; retrying entrypoint bind"
                );
                last_bind_error = Some(err);
            }
            Err(err) => return Err(err.into()),
        }
    }

    let detail = last_bind_error
        .map(|err| err.to_string())
        .unwrap_or_else(|| "no retryable bind error was recorded".to_owned());
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!(
            "failed to bind a TCP/UDP entrypoint pair for {address} after {DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS} attempts: {detail}"
        ),
    )
    .into())
}

fn dynamic_entrypoint_bind_candidate(address: SocketAddr, attempt: usize) -> SocketAddr {
    if attempt == 1 {
        return address;
    }
    SocketAddr::new(
        address.ip(),
        rand::rng().random_range(DYNAMIC_ENTRYPOINT_MIN_PORT..=DYNAMIC_ENTRYPOINT_MAX_PORT),
    )
}

fn dynamic_bind_error_is_retryable(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
    )
}

async fn bind_entrypoint_socket_pair_once(
    address: SocketAddr,
) -> Result<(tokio::net::TcpListener, Arc<tokio::net::UdpSocket>), Box<dyn std::error::Error>> {
    let tcp_listener = tokio::net::TcpListener::bind(address).await?;
    let bound_address = tcp_listener.local_addr()?;
    let udp_socket = Arc::new(tokio::net::UdpSocket::bind(bound_address).await?);
    Ok((tcp_listener, udp_socket))
}

#[derive(Debug, Clone)]
struct EntrypointListenSpec {
    address: SocketAddr,
    server_id: String,
    udp_ping_status_server_id: String,
}

fn normalize_sni_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

async fn bind_entrypoints(
    config: &Config,
) -> Result<EntrypointBindings, Box<dyn std::error::Error>> {
    let mut tcp_listeners = Vec::new();
    let mut udp_sockets = Vec::new();
    let mut udp_socket_by_port = HashMap::new();
    let mut server_id_by_port = HashMap::new();
    let mut udp_ping_status_server_id_by_port = HashMap::new();

    let (server_id_by_sni, listen_specs) = entrypoint_config_routes(config)?;

    let listen_address = first_socket_addr(&config.listen)?;
    let (listener, udp_socket) = bind_entrypoint_socket_pair(listen_address).await?;
    let default_port = listener.local_addr()?.port();
    udp_socket_by_port.insert(default_port, Arc::clone(&udp_socket));
    udp_sockets.push(udp_socket);
    tcp_listeners.push(ServerTcpListener {
        listener: Arc::new(listener),
    });

    for spec in listen_specs {
        let EntrypointListenSpec {
            address,
            server_id,
            udp_ping_status_server_id,
        } = spec;
        let (listener, udp_socket) = bind_entrypoint_socket_pair(address).await?;
        let port = listener.local_addr()?.port();
        if port == default_port {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("server entrypoint for {server_id} reuses the default TCP/UDP port {port}"),
            )
            .into());
        }
        if let Some(existing) = server_id_by_port.insert(port, server_id.clone()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "multiple server entrypoints bind TCP/UDP port {port}: {existing} and {server_id}"
                ),
            )
            .into());
        }
        udp_ping_status_server_id_by_port.insert(port, udp_ping_status_server_id);
        udp_socket_by_port.insert(port, Arc::clone(&udp_socket));
        udp_sockets.push(udp_socket);
        tcp_listeners.push(ServerTcpListener {
            listener: Arc::new(listener),
        });
    }

    Ok(EntrypointBindings {
        default_port,
        tcp_listeners,
        udp_sockets,
        udp_socket_by_port,
        server_id_by_port,
        udp_ping_status_server_id_by_port,
        server_id_by_sni,
    })
}

fn register_sni_entrypoints(
    server_id_by_sni: &mut HashMap<String, String>,
    entrypoint: &ServerEntrypointConfig,
    server_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for sni in &entrypoint.sni {
        let sni = normalize_sni_name(sni);
        if sni.is_empty() {
            continue;
        }
        if let Some(existing) = server_id_by_sni.insert(sni.clone(), server_id.to_owned()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SNI name {sni} is mapped to both {existing} and {server_id}"),
            )
            .into());
        }
    }
    Ok(())
}

fn entrypoint_config_routes(
    config: &Config,
) -> Result<(HashMap<String, String>, Vec<EntrypointListenSpec>), Box<dyn std::error::Error>> {
    let mut server_id_by_sni = HashMap::new();
    let mut listen_specs = Vec::new();
    let mut fixed_port_owners: HashMap<u16, String> = HashMap::new();

    for entrypoint in &config.server_entrypoints {
        let server_id = entrypoint.server_id.trim();
        if server_id.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server_entrypoints entries require non-empty server_id",
            )
            .into());
        }

        register_sni_entrypoints(&mut server_id_by_sni, entrypoint, server_id)?;

        let Some(listen) = entrypoint.listen.as_deref() else {
            continue;
        };
        let udp_ping_status_server_id = entrypoint
            .udp_ping_status_server_id
            .as_deref()
            .map(str::trim)
            .unwrap_or(server_id);
        if udp_ping_status_server_id.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("server entrypoint for {server_id} has empty udp_ping_status_server_id"),
            )
            .into());
        }
        let address = first_socket_addr(listen)?;
        if address.port() != 0 {
            if let Some(existing) = fixed_port_owners.insert(address.port(), server_id.to_owned()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "multiple server entrypoints bind TCP/UDP port {}: {} and {}",
                        address.port(),
                        existing,
                        server_id
                    ),
                )
                .into());
            }
        }
        listen_specs.push(EntrypointListenSpec {
            address,
            server_id: server_id.to_owned(),
            udp_ping_status_server_id: udp_ping_status_server_id.to_owned(),
        });
    }

    Ok((server_id_by_sni, listen_specs))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::api::{
        AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
    };
    use crate::localization::Language;
    use crate::messages::encoder::TextMessage;
    use crate::voice::codec::PacketFormat;
    use crate::voice::ping::PingRequest;
    use rustls::pki_types::ServerName;
    use std::sync::OnceLock;
    use tokio_rustls::TlsConnector;

    struct TestAuthenticator;

    fn install_default_provider() {
        static CRYPTO_PROVIDER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        CRYPTO_PROVIDER.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[async_trait::async_trait]
    impl Authenticator for TestAuthenticator {
        async fn authenticate(
            &self,
            username: &str,
            _password: Option<&str>,
            _auxiliary_data: &AuthenticateAuxiliaryData,
        ) -> Result<AuthenticateResult, AuthenticationRejection> {
            Ok(AuthenticateResult {
                user_id: None,
                display_name: Some(username.to_owned()),
                groups: Vec::new(),
                is_superuser: false,
                virtual_server_id: None,
                language: Language::default(),
                max_bandwidth: None,
                texture_url: None,
                comment_url: None,
            })
        }
    }

    fn test_config(entrypoints: Vec<ServerEntrypointConfig>) -> Config {
        let identity = default_test_identity();
        Config {
            listen: "127.0.0.1:0".to_owned(),
            server_entrypoints: entrypoints,
            register_name: "test".to_owned(),
            register_password: None,
            register_url: None,
            register_hostname: None,
            register_location: None,
            cert_path: identity.cert_path.clone(),
            key_path: identity.key_path.clone(),
            send_version: false,
            send_build_info: false,
            send_os_info: false,
            server_protocol_version: crate::constants::APP_PROTO_VER,
            allowed_proxies: Vec::new(),
            min_client_version: 0,
            max_users: 100,
            authenticator: AuthenticatorConfig::default(),
            observability: crate::config::ObservabilityConfig::default(),
            geoip: crate::config::GeoIpConfig::default(),
            welcome_text: None,
            max_bandwidth: 72_000,
            allow_html: true,
            max_text_message_length: 5_000,
            max_image_message_length: 131_072,
            root_channel_name: "Root".to_owned(),
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
            authenticate_timeout_ms: 30_000,
            auth_finalization_concurrency: 4,
            pending_delete_timeout_ms: 5_000,
            required_groups: Vec::new(),
            send_permission_info: false,
            hide_users_without_traverse: false,
            acl: crate::config::AclConfig::default(),
            s2s: crate::config::S2sConfig::default(),
            web: crate::config::WebConfig::default(),
            privacy: crate::config::PrivacyConfig::default(),
        }
    }

    struct TestIdentityFixture {
        _dir: tempfile::TempDir,
        cert_path: String,
        key_path: String,
    }

    fn default_test_identity() -> &'static TestIdentityFixture {
        static IDENTITY: OnceLock<TestIdentityFixture> = OnceLock::new();
        IDENTITY.get_or_init(|| {
            let dir = tempfile::tempdir().expect("test identity tempdir");
            let (cert_path, key_path, _) = write_test_cert(dir.path(), "default");
            TestIdentityFixture {
                _dir: dir,
                cert_path,
                key_path,
            }
        })
    }

    fn write_test_cert(dir: &std::path::Path, name: &str) -> (String, String, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate test cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .expect("test cert PEM contains a certificate")
            .expect("parse test cert")
            .to_vec();

        let cert_path = dir.join(format!("{name}-cert.pem"));
        let key_path = dir.join(format!("{name}-key.pem"));
        std::fs::write(&cert_path, cert_pem).expect("write test cert");
        std::fs::write(&key_path, key_pem).expect("write test key");

        (
            cert_path.display().to_string(),
            key_path.display().to_string(),
            cert_der,
        )
    }

    struct TestTlsHandshake {
        leaf_der: Vec<u8>,
        protocol_version: rustls::ProtocolVersion,
        cipher_suite: rustls::CipherSuite,
        key_exchange_group: Option<rustls::NamedGroup>,
        handshake_kind: rustls::HandshakeKind,
    }

    async fn connect_tls(server: &Arc<Box<Server>>) -> TestTlsHandshake {
        let acceptor = server.tls_acceptor.read().clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let accept_task = tokio::spawn(async move { acceptor.accept(server_io).await.map(drop) });

        let cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let tls = connector
            .connect(
                ServerName::try_from("localhost").expect("static server name"),
                client_io,
            )
            .await
            .expect("client TLS handshake");
        let leaf = tls
            .get_ref()
            .1
            .peer_certificates()
            .expect("server certificate chain")
            .first()
            .expect("server leaf certificate")
            .to_vec();
        let connection = tls.get_ref().1;
        let protocol_version = connection.protocol_version().expect("TLS protocol version");
        let cipher_suite = connection
            .negotiated_cipher_suite()
            .expect("negotiated cipher suite")
            .suite();
        let key_exchange_group = connection
            .negotiated_key_exchange_group()
            .map(|group| group.name());
        let handshake_kind = connection.handshake_kind().expect("TLS handshake kind");
        drop(tls);
        match accept_task.await.expect("accept task joins") {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(err) => panic!("accept TLS: {err}"),
        }
        TestTlsHandshake {
            leaf_der: leaf,
            protocol_version,
            cipher_suite,
            key_exchange_group,
            handshake_kind,
        }
    }

    async fn connect_tls_leaf_der(server: &Arc<Box<Server>>) -> Vec<u8> {
        connect_tls(server).await.leaf_der
    }

    async fn assert_config_read_completes_during_root_channel_reload(
        server: &Arc<Box<Server>>,
        next_root_name: &str,
    ) {
        let next_root = ChannelRootConfig::new(next_root_name);
        let root_update = {
            let current = server.config.write().expect("Config RwLock poisoned");
            assert_ne!(current.root_channel_name, next_root.name());
            Some(next_root)
        };

        let root_update = tokio::spawn({
            let channels = Arc::clone(&server.channels);
            async move {
                if let Some(root_update) = root_update {
                    channels.update_root_channel_config(root_update).await;
                }
            }
        });
        tokio::task::yield_now().await;

        tokio::time::timeout(Duration::from_millis(50), async {
            let config = server.read_config();
            assert_eq!(config.root_channel_name, "Root");
        })
        .await
        .expect("config read should not wait for async channel reload work");

        root_update.await.expect("root channel update task joins");
    }

    fn auth_queue_test_client(
        session: u32,
    ) -> (Arc<Box<Client>>, tokio::sync::mpsc::Receiver<Message>) {
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_000 + session as u16);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000 + session as u16);
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(8);
        let client = Client::new_web_gateway(
            ClientSessionIdentifier::new(1, session).expect("test session id"),
            peer.ip(),
            peer,
            local,
            outbound_tx,
        );
        (Arc::new(client), outbound_rx)
    }

    async fn recv_auth_queue_notice(rx: &mut tokio::sync::mpsc::Receiver<Message>) -> String {
        let message = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("queue notice should arrive")
            .expect("queue notice channel should remain open");
        let Message::TextMessage(text) = message else {
            panic!("expected queue notice TextMessage, got {message:?}");
        };
        text.message
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
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    #[tokio::test]
    async fn bind_entrypoints_maps_default_and_extra_ports() {
        let config = test_config(vec![ServerEntrypointConfig {
            server_id: "tenant-a".to_owned(),
            listen: Some("127.0.0.1:0".to_owned()),
            udp_ping_status_server_id: None,
            sni: Vec::new(),
        }]);

        let bindings = bind_entrypoints(&config).await.expect("entrypoints bind");

        assert_eq!(bindings.tcp_listeners.len(), 2);
        assert_eq!(bindings.udp_sockets.len(), 2);
        assert!(
            !bindings.server_id_by_port.contains_key(
                &bindings.tcp_listeners[0]
                    .listener
                    .local_addr()
                    .unwrap()
                    .port()
            )
        );
        assert_eq!(
            bindings
                .server_id_by_port
                .get(
                    &bindings.tcp_listeners[1]
                        .listener
                        .local_addr()
                        .unwrap()
                        .port()
                )
                .map(String::as_str),
            Some("tenant-a")
        );
        assert_eq!(
            bindings
                .udp_ping_status_server_id_by_port
                .get(
                    &bindings.tcp_listeners[1]
                        .listener
                        .local_addr()
                        .unwrap()
                        .port()
                )
                .map(String::as_str),
            Some("tenant-a")
        );
    }

    #[tokio::test]
    async fn bind_entrypoints_maps_udp_ping_status_override() {
        let config = test_config(vec![ServerEntrypointConfig {
            server_id: "tenant-a".to_owned(),
            listen: Some("127.0.0.1:0".to_owned()),
            udp_ping_status_server_id: Some("tenant-a-status".to_owned()),
            sni: Vec::new(),
        }]);

        let bindings = bind_entrypoints(&config).await.expect("entrypoints bind");
        let port = bindings.tcp_listeners[1]
            .listener
            .local_addr()
            .unwrap()
            .port();

        assert_eq!(
            bindings.server_id_by_port.get(&port).map(String::as_str),
            Some("tenant-a")
        );
        assert_eq!(
            bindings
                .udp_ping_status_server_id_by_port
                .get(&port)
                .map(String::as_str),
            Some("tenant-a-status")
        );
    }

    #[test]
    fn register_sni_entrypoints_normalizes_names() {
        let entrypoint = ServerEntrypointConfig {
            server_id: "tenant-a".to_owned(),
            listen: None,
            udp_ping_status_server_id: None,
            sni: vec!["Tenant-A.Example.Test.".to_owned()],
        };
        let mut map = HashMap::new();

        register_sni_entrypoints(&mut map, &entrypoint, &entrypoint.server_id)
            .expect("SNI entrypoint");

        assert_eq!(
            map.get("tenant-a.example.test").map(String::as_str),
            Some("tenant-a")
        );
    }

    #[test]
    fn dynamic_bind_retry_covers_windows_permission_denied() {
        assert!(dynamic_bind_error_is_retryable(&std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "port already in use"
        )));
        assert!(dynamic_bind_error_is_retryable(&std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "port excluded by the OS"
        )));
        assert!(!dynamic_bind_error_is_retryable(&std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a bind race"
        )));
    }

    #[test]
    fn dynamic_bind_retry_randomizes_candidates_after_first_attempt() {
        let address: SocketAddr = "127.0.0.1:0".parse().unwrap();

        assert_eq!(dynamic_entrypoint_bind_candidate(address, 1), address);

        let candidate = dynamic_entrypoint_bind_candidate(address, 2);
        assert_eq!(candidate.ip(), address.ip());
        assert!(
            (DYNAMIC_ENTRYPOINT_MIN_PORT..=DYNAMIC_ENTRYPOINT_MAX_PORT).contains(&candidate.port())
        );
    }

    #[test]
    fn c2s_tls_provider_only_advertises_pfs_cipher_suites() {
        let provider = c2s_pfs_tls_provider();

        assert!(!provider.cipher_suites.is_empty());
        assert!(provider.kx_groups.iter().any(|group| {
            group.name().key_exchange_algorithm() == rustls::crypto::KeyExchangeAlgorithm::ECDHE
        }));
        for suite in &provider.cipher_suites {
            assert!(
                c2s_cipher_suite_provides_pfs(suite),
                "non-PFS C2S cipher suite left enabled: {:?}",
                suite.suite()
            );
        }
    }

    #[test]
    fn c2s_tls_config_disables_session_resumption() {
        install_default_provider();
        let temp = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path, _) = write_test_cert(temp.path(), "c2s");
        let mut config = test_config(Vec::new());
        config.cert_path = cert_path;
        config.key_path = key_path;

        let tls_config =
            load_c2s_tls_config(&config, &ServerExtensions::default()).expect("C2S TLS config");

        assert!(!tls_config.session_storage.can_cache());
        assert_eq!(tls_config.send_tls13_tickets, 0);
    }

    #[tokio::test]
    async fn c2s_tls_handshake_negotiates_ephemeral_key_exchange() {
        install_default_provider();
        let temp = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path, _) = write_test_cert(temp.path(), "c2s");
        let mut config = test_config(Vec::new());
        config.cert_path = cert_path;
        config.key_path = key_path;
        let server = Server::new(config, TestAuthenticator)
            .await
            .expect("server");

        let tls = connect_tls(&server).await;

        assert_eq!(tls.protocol_version, rustls::ProtocolVersion::TLSv1_3);
        assert!(matches!(
            tls.cipher_suite,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        ));
        assert!(tls.key_exchange_group.is_some());
        assert_eq!(tls.handshake_kind, rustls::HandshakeKind::Full);
    }

    #[tokio::test]
    async fn apply_entrypoint_config_accepts_config_absent_server_id_scope() {
        install_default_provider();
        let server = Server::new(test_config(Vec::new()), TestAuthenticator)
            .await
            .expect("server");
        let new_config = test_config(vec![ServerEntrypointConfig {
            server_id: "tenant-from-existing-state".to_owned(),
            listen: Some("127.0.0.1:0".to_owned()),
            udp_ping_status_server_id: None,
            sni: vec!["Tenant.Example.Test".to_owned()],
        }]);

        server
            .apply_entrypoint_config(&new_config)
            .await
            .expect("apply entrypoint config");

        let entrypoints = server.entrypoints.read();
        assert_eq!(
            entrypoints
                .server_id_by_sni
                .get("tenant.example.test")
                .map(String::as_str),
            Some("tenant-from-existing-state")
        );
        assert!(
            entrypoints
                .server_id_by_port
                .values()
                .any(|server_id| { server_id == "tenant-from-existing-state" })
        );
    }

    #[tokio::test]
    async fn reload_c2s_tls_identity_swaps_acceptor_for_new_handshakes() {
        install_default_provider();
        let temp = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path, first_leaf) = write_test_cert(temp.path(), "first");
        let mut config = test_config(Vec::new());
        config.cert_path = cert_path;
        config.key_path = key_path;
        let server = Server::new(config.clone(), TestAuthenticator)
            .await
            .expect("server");

        assert_eq!(connect_tls_leaf_der(&server).await, first_leaf);

        let (next_cert_path, next_key_path, next_leaf) = write_test_cert(temp.path(), "next");
        let mut next_config = config;
        next_config.cert_path = next_cert_path;
        next_config.key_path = next_key_path;

        server
            .reload_c2s_tls_identity(&next_config)
            .expect("reload C2S TLS identity");

        assert_eq!(connect_tls_leaf_der(&server).await, next_leaf);
    }

    #[tokio::test]
    async fn reload_c2s_tls_identity_keeps_current_acceptor_on_invalid_identity() {
        install_default_provider();
        let temp = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path, first_leaf) = write_test_cert(temp.path(), "first");
        let mut config = test_config(Vec::new());
        config.cert_path = cert_path;
        config.key_path = key_path;
        let server = Server::new(config.clone(), TestAuthenticator)
            .await
            .expect("server");

        let (next_cert_path, next_key_path, _next_leaf) = write_test_cert(temp.path(), "next");
        std::fs::write(&next_key_path, "not a private key").expect("write invalid key");
        let mut next_config = config;
        next_config.cert_path = next_cert_path;
        next_config.key_path = next_key_path;

        assert!(server.reload_c2s_tls_identity(&next_config).is_err());
        assert_eq!(connect_tls_leaf_der(&server).await, first_leaf);
    }

    #[tokio::test]
    async fn idle_reaper_only_disconnects_local_clients() {
        install_default_provider();
        let server = Server::new(test_config(Vec::new()), TestAuthenticator)
            .await
            .expect("server");

        let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::channel(1);
        let local_client = server
            .clients
            .allocate_web_client_in_server(
                DEFAULT_SERVER_ID,
                "127.0.0.1".parse().unwrap(),
                "127.0.0.1:50000".parse().unwrap(),
                "127.0.0.1:50001".parse().unwrap(),
                outbound_tx,
            )
            .await;
        let local_sid = local_client.get_session_id();

        let remote_sid = ClientSessionIdentifier::new(2, 1).unwrap();
        let remote_client = Arc::new(Client::new_remote_in_server(
            DEFAULT_SERVER_ID.to_owned(),
            remote_sid,
            "127.0.0.2".parse().unwrap(),
            "127.0.0.2:50000".parse().unwrap(),
            None,
            "127.0.0.1:50000".parse().unwrap(),
            None,
            chrono::Utc::now() - chrono::Duration::seconds(60),
            7,
        ));
        server
            .clients
            .add_remote_client(remote_sid, Arc::clone(&remote_client))
            .await;

        server
            .disconnect_idle_local_clients(chrono::Utc::now() + chrono::Duration::seconds(1), 0)
            .await;

        assert!(
            server
                .clients
                .get_client_in_server(DEFAULT_SERVER_ID, local_sid)
                .await
                .is_none()
        );
        assert!(
            server
                .clients
                .get_client_in_server(DEFAULT_SERVER_ID, remote_sid)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn udp_ping_response_does_not_wait_for_blocked_client_broadcast() {
        install_default_provider();
        let mut config = test_config(Vec::new());
        config.udp_ping_user_count_scope = UdpPingUserCountScope::Local;
        let server = Server::new(config, TestAuthenticator)
            .await
            .expect("server");

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30001);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let client = server
            .clients
            .allocate_web_client_in_server(DEFAULT_SERVER_ID, peer.ip(), peer, local, tx)
            .await;
        let prefill = Message::TextMessage(
            TextMessage {
                actor: Some(12),
                session: Vec::new(),
                channel_id: Vec::new(),
                tree_id: Vec::new(),
                message: "prefill".to_string(),
            }
            .into(),
        );
        client.write_proto_message(&prefill).await.unwrap();

        let broadcast_message = Message::TextMessage(
            TextMessage {
                actor: Some(12),
                session: Vec::new(),
                channel_id: Vec::new(),
                tree_id: Vec::new(),
                message: "blocked broadcast".to_string(),
            }
            .into(),
        );
        let broadcast = tokio::spawn({
            let clients = Arc::clone(&server.clients);
            async move {
                clients
                    .broadcast_all_in_server(DEFAULT_SERVER_ID, &broadcast_message)
                    .await;
            }
        });
        tokio::task::yield_now().await;

        let writer = tokio::spawn({
            let clients = Arc::clone(&server.clients);
            async move {
                clients
                    .remove_client_in_server(DEFAULT_SERVER_ID, client.get_session_id())
                    .await;
            }
        });
        tokio::task::yield_now().await;

        let ping = PingRequest {
            timestamp: 42,
            request_extended_information: false,
            format: PacketFormat::Legacy,
        };
        let reply = tokio::time::timeout(
            Duration::from_millis(50),
            Server::build_ping_response(&server, &ping, DEFAULT_SERVER_ID),
        )
        .await
        .expect("UDP status ping should not wait behind a blocked broadcast")
        .expect("ping response encodes");
        assert!(!reply.is_empty());

        writer.abort();
        let _ = writer.await;
        broadcast.abort();
        let _ = broadcast.await;
    }

    #[tokio::test]
    async fn activate_subscriptions_fast_path_replays_missed_client_add() {
        install_default_provider();
        let server = Server::new(test_config(Vec::new()), TestAuthenticator)
            .await
            .expect("server");

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31001);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
        let (viewer_tx, mut viewer_rx) = tokio::sync::mpsc::channel(16);
        let viewer = server
            .clients
            .allocate_web_client_in_server(DEFAULT_SERVER_ID, peer.ip(), peer, local, viewer_tx)
            .await;
        viewer.set_authenticated(true);
        let viewer_session = viewer.get_session_id();

        let (_clients, versions, client_state_rx) = server
            .clients
            .snapshot_with_versions_and_subscription_in_server(DEFAULT_SERVER_ID)
            .await;
        viewer.stage_client_state_subscription(client_state_rx);
        viewer.update_last_client_versions(&versions).await;

        let (channels, channel_version, channel_state_rx) = server
            .channels
            .snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
        viewer.stage_channel_state_subscription(channel_version, channel_state_rx);
        viewer.stage_post_auth_baseline(crate::client::PostAuthBaseline::new(
            HashMap::from([(viewer_session, viewer.get_current_channel_id())]),
            channels.iter().map(|channel| channel.id).collect(),
        ));

        let target_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31002);
        let target_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64739);
        let (target_tx, _target_rx) = tokio::sync::mpsc::channel(1);
        let target = server
            .clients
            .allocate_web_client_in_server(
                DEFAULT_SERVER_ID,
                target_peer.ip(),
                target_peer,
                target_local,
                target_tx,
            )
            .await;
        target.set_authenticated(true);
        let target_session = target.get_session_id();
        server
            .clients
            .publish_client_in_server(DEFAULT_SERVER_ID, target_session)
            .await;

        let mut client_log_rx = None;
        let mut channel_log_rx = None;
        let mut channel_tree_shadow = ChannelTreeShadow::default();
        let mut session_channel_shadow = SessionChannelShadow::default();
        let mut user_visibility = UserVisibilityState::default();

        activate_client_subscriptions(
            &server,
            &viewer,
            viewer_session,
            &mut client_log_rx,
            &mut channel_log_rx,
            &mut channel_tree_shadow,
            &mut session_channel_shadow,
            &mut user_visibility,
        )
        .await
        .expect("activation succeeds");

        let replayed_target = tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(message) = viewer_rx.recv().await {
                if matches!(message, Message::UserState(user) if user.session == Some(u32::from(target_session)))
                {
                    return true;
                }
            }
            false
        })
        .await
        .expect("activation should write replayed target UserState");

        assert!(replayed_target);
        assert_eq!(
            session_channel_shadow.get(&target_session).copied(),
            Some(target.get_current_channel_id())
        );
        assert_eq!(user_visibility.known_channel(target_session), None);
    }

    #[test]
    fn auth_finalization_queue_notice_is_sent_only_when_position_changes() {
        let mut last_announced_position = None;

        assert!(should_send_auth_finalization_queue_notice(
            &mut last_announced_position,
            2
        ));
        assert_eq!(last_announced_position, Some(2));

        assert!(!should_send_auth_finalization_queue_notice(
            &mut last_announced_position,
            2
        ));
        assert_eq!(last_announced_position, Some(2));

        assert!(should_send_auth_finalization_queue_notice(
            &mut last_announced_position,
            1
        ));
        assert_eq!(last_announced_position, Some(1));
    }

    #[test]
    fn auth_finalization_queue_keeps_new_arrivals_behind_existing_waiters() {
        let queue = Arc::new(AuthFinalizationQueue::new(
            1,
            ReloadableAuthenticator::fixed(TestAuthenticator),
        ));

        let first_permit = match queue.reserve_or_queue() {
            AuthFinalizationAdmission::Immediate(permit) => permit,
            AuthFinalizationAdmission::Queued(_) => {
                panic!("first acquire should use the free permit")
            }
        };
        let second_ticket = match queue.reserve_or_queue() {
            AuthFinalizationAdmission::Queued(ticket) => ticket,
            AuthFinalizationAdmission::Immediate(_) => panic!("second acquire should queue"),
        };

        drop(first_permit);

        let third_ticket = match queue.reserve_or_queue() {
            AuthFinalizationAdmission::Queued(ticket) => ticket,
            AuthFinalizationAdmission::Immediate(_) => {
                panic!("new arrival must not bypass an existing queued waiter")
            }
        };

        assert_eq!(queue.position(second_ticket), Some(1));
        assert_eq!(queue.position(third_ticket), Some(2));
    }

    #[tokio::test]
    async fn auth_finalization_queue_admits_waiters_fifo() {
        let queue = Arc::new(AuthFinalizationQueue::new(
            1,
            ReloadableAuthenticator::fixed(TestAuthenticator),
        ));
        let (first_client, _first_rx) = auth_queue_test_client(1);
        let first_permit = queue
            .acquire(&first_client)
            .await
            .expect("first client should acquire immediately");

        let (second_client, mut second_rx) = auth_queue_test_client(2);
        let second_queue = Arc::clone(&queue);
        let mut second_task =
            tokio::spawn(async move { second_queue.acquire(&second_client).await });
        let second_notice = recv_auth_queue_notice(&mut second_rx).await;
        assert!(
            second_notice.contains("You're in the login queue. There are 0 users ahead of you."),
            "unexpected second notice text: {second_notice}"
        );

        let (third_client, mut third_rx) = auth_queue_test_client(3);
        let third_queue = Arc::clone(&queue);
        let mut third_task = tokio::spawn(async move { third_queue.acquire(&third_client).await });
        let third_notice = recv_auth_queue_notice(&mut third_rx).await;
        assert!(
            third_notice.contains("You're in the login queue. There are 1 users ahead of you."),
            "unexpected third notice text: {third_notice}"
        );

        drop(first_permit);

        tokio::select! {
            second = &mut second_task => {
                let second_permit = second
                    .expect("second acquire task should join")
                    .expect("second client should acquire next");

                assert!(
                    tokio::time::timeout(Duration::from_millis(50), &mut third_task)
                        .await
                        .is_err(),
                    "third client acquired before the first queued client released its permit"
                );

                drop(second_permit);
                let _third_permit = tokio::time::timeout(Duration::from_secs(1), third_task)
                    .await
                    .expect("third client should acquire after second releases")
                    .expect("third acquire task should join")
                    .expect("third client should acquire");
            }
            third = &mut third_task => {
                third.expect("third acquire task should join")
                    .expect("third acquire should not fail");
                panic!("third client acquired before the first queued client");
            }
        }
    }

    #[tokio::test]
    async fn reload_root_channel_work_does_not_hold_config_write_lock() {
        install_default_provider();
        let server = Server::new(test_config(Vec::new()), TestAuthenticator)
            .await
            .expect("server");

        assert_config_read_completes_during_root_channel_reload(&server, "Renamed Root").await;
    }
}

pub struct Server {
    node_identifier: NodeIdentifier,

    // Shared config — can be hot-reloaded at runtime
    config: Arc<StdRwLock<Config>>,

    allowed_proxies: Vec<AnyIpCidr>,

    tls_acceptor: ParkingRwLock<TlsAcceptor>,
    extensions: ServerExtensions,
    entrypoints: Arc<ParkingRwLock<EntrypointBindings>>,
    entrypoint_runtime: Mutex<Option<EntrypointRuntime>>,
    entrypoint_reload_lock: tokio::sync::Mutex<()>,

    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
    auth_finalization_queue: Arc<AuthFinalizationQueue>,
    crypt_setup_semaphore: Arc<tokio::sync::Semaphore>,
    channel_blobs: Arc<ChannelBlobStore>,
    session_blobs: Arc<SessionBlobStore>,
    user_channel_cache: Arc<UserChannelCache>,
    bans: Arc<crate::ban_repository::BanRepository>,

    codec_info: Mutex<CodecInfo>,

    /// Registry of server-defined context menu actions.
    context_actions: Arc<crate::context_action::ContextActionRegistry>,

    s2s_manager: Arc<S2SManager>,
    geoip_resolver: ParkingRwLock<Arc<GeoIpResolver>>,
    shutdown_tx: tokio::sync::watch::Sender<()>,
}

#[derive(Clone)]
struct ServerTcpListener {
    listener: Arc<tokio::net::TcpListener>,
}

struct EntrypointBindings {
    default_port: u16,
    tcp_listeners: Vec<ServerTcpListener>,
    udp_sockets: Vec<Arc<tokio::net::UdpSocket>>,
    udp_socket_by_port: HashMap<u16, Arc<tokio::net::UdpSocket>>,
    server_id_by_port: HashMap<u16, String>,
    udp_ping_status_server_id_by_port: HashMap<u16, String>,
    server_id_by_sni: HashMap<String, String>,
}

#[derive(Clone)]
struct EntrypointRuntime {
    udp_in: tokio::sync::mpsc::Sender<UdpPacket>,
    udp_voice_enabled: bool,
    udp_ping_enabled: bool,
    shutdown: tokio::sync::watch::Receiver<()>,
}

struct AuthFinalizationQueue {
    authenticator: Arc<ReloadableAuthenticator>,
    semaphore: Arc<tokio::sync::Semaphore>,
    next_ticket: AtomicU64,
    waiters: Mutex<VecDeque<AuthFinalizationWaiter>>,
    waiters_changed: tokio::sync::Notify,
    #[cfg(test)]
    test_gate: Mutex<Option<AuthFinalizationTestGate>>,
}

#[derive(Clone)]
struct AuthFinalizationWaiter {
    ticket: u64,
}

enum AuthFinalizationAdmission {
    Immediate(tokio::sync::OwnedSemaphorePermit),
    Queued(u64),
}

#[cfg(test)]
struct AuthFinalizationTestGate {
    target_acquire: usize,
    acquired_count: std::sync::atomic::AtomicUsize,
    entered_tx: tokio::sync::watch::Sender<usize>,
    release_rx: tokio::sync::watch::Receiver<bool>,
}

#[cfg(test)]
pub struct AuthFinalizationTestGateHandle {
    entered_rx: tokio::sync::watch::Receiver<usize>,
    release_tx: tokio::sync::watch::Sender<bool>,
}

#[cfg(test)]
impl AuthFinalizationTestGateHandle {
    pub async fn wait_entered(&mut self, deadline: Duration) -> Option<usize> {
        tokio::time::timeout(deadline, async {
            loop {
                let value = *self.entered_rx.borrow();
                if value != 0 {
                    return value;
                }
                if self.entered_rx.changed().await.is_err() {
                    return 0;
                }
            }
        })
        .await
        .ok()
        .filter(|value| *value != 0)
    }

    pub fn release(&self) {
        let _ = self.release_tx.send(true);
    }
}

pub struct AuthFinalizationPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    queue: Arc<AuthFinalizationQueue>,
    ticket: u64,
}

impl AuthFinalizationQueue {
    fn new(limit: usize, authenticator: ReloadableAuthenticator) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
            semaphore: Arc::new(tokio::sync::Semaphore::new(limit.max(1))),
            next_ticket: AtomicU64::new(1),
            waiters: Mutex::new(VecDeque::new()),
            waiters_changed: tokio::sync::Notify::new(),
            #[cfg(test)]
            test_gate: Mutex::new(None),
        }
    }

    fn authenticator(&self) -> &dyn Authenticator {
        self.authenticator.as_ref()
    }

    fn authenticator_arc(&self) -> Arc<dyn Authenticator> {
        let authenticator: Arc<dyn Authenticator> = self.authenticator.clone();
        authenticator
    }

    fn prepare_authenticator_reload(
        &self,
        config: &Config,
    ) -> Result<Option<Arc<dyn Authenticator>>, crate::api::AuthenticatorBackendError> {
        self.authenticator.prepare_reload(config)
    }

    fn apply_prepared_authenticator_reload(&self, next: Option<Arc<dyn Authenticator>>) {
        self.authenticator.apply_prepared_reload(next);
    }

    async fn acquire(
        self: &Arc<Self>,
        client: &Arc<Box<Client>>,
    ) -> Result<AuthFinalizationPermit, MessageHandlerError> {
        let ticket = match self.reserve_or_queue() {
            AuthFinalizationAdmission::Immediate(permit) => {
                self.wait_for_test_gate_if_needed().await;
                return Ok(AuthFinalizationPermit {
                    _permit: permit,
                    queue: Arc::clone(self),
                    ticket: 0,
                });
            }
            AuthFinalizationAdmission::Queued(ticket) => ticket,
        };

        let waiter = AuthFinalizationTicket {
            queue: Arc::clone(self),
            ticket,
        };
        let mut last_announced_position = None;
        self.send_queue_notice(client, ticket, &mut last_announced_position)
            .await?;
        let permit = self
            .acquire_queued_permit(client, ticket, &mut last_announced_position)
            .await?;

        drop(waiter);
        self.wait_for_test_gate_if_needed().await;
        Ok(AuthFinalizationPermit {
            _permit: permit,
            queue: Arc::clone(self),
            ticket,
        })
    }

    fn reserve_or_queue(self: &Arc<Self>) -> AuthFinalizationAdmission {
        let mut waiters = self.waiters.lock();
        if waiters.is_empty()
            && let Ok(permit) = Arc::clone(&self.semaphore).try_acquire_owned()
        {
            return AuthFinalizationAdmission::Immediate(permit);
        }

        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        waiters.push_back(AuthFinalizationWaiter { ticket });
        AuthFinalizationAdmission::Queued(ticket)
    }

    async fn acquire_queued_permit(
        self: &Arc<Self>,
        client: &Arc<Box<Client>>,
        ticket: u64,
        last_announced_position: &mut Option<usize>,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, MessageHandlerError> {
        let mut notice_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + AUTH_FINALIZATION_QUEUE_NOTICE_INTERVAL,
            AUTH_FINALIZATION_QUEUE_NOTICE_INTERVAL,
        );
        notice_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let waiters_changed = self.waiters_changed.notified();
            tokio::pin!(waiters_changed);

            if !self.is_front(ticket) {
                tokio::select! {
                    _ = &mut waiters_changed => {}
                    _ = notice_interval.tick() => {
                        self.send_queue_notice(client, ticket, last_announced_position).await?;
                    }
                }
                continue;
            }

            let permit = Arc::clone(&self.semaphore).acquire_owned();
            tokio::pin!(permit);
            loop {
                tokio::select! {
                    permit = &mut permit => {
                        return Ok(permit.expect("auth finalization semaphore should not be closed"));
                    }
                    _ = notice_interval.tick() => {
                        self.send_queue_notice(client, ticket, last_announced_position).await?;
                    }
                }
            }
        }
    }

    async fn send_queue_notice(
        &self,
        client: &Arc<Box<Client>>,
        ticket: u64,
        last_announced_position: &mut Option<usize>,
    ) -> Result<(), MessageHandlerError> {
        if let Some(position) = self.position(ticket)
            && should_send_auth_finalization_queue_notice(last_announced_position, position)
        {
            let message = auth_finalization_queue_message(client.get_session_id(), position);
            client.write_proto_message(&message).await?;
        }
        Ok(())
    }

    fn remove_waiter(&self, ticket: u64) {
        if ticket != 0 {
            let removed = {
                let mut waiters = self.waiters.lock();
                let before = waiters.len();
                waiters.retain(|waiter| waiter.ticket != ticket);
                waiters.len() != before
            };
            if removed {
                self.waiters_changed.notify_waiters();
            }
        }
    }

    fn is_front(&self, ticket: u64) -> bool {
        let waiters = self.waiters.lock();
        waiters
            .front()
            .is_some_and(|waiter| waiter.ticket == ticket)
    }

    fn position(&self, ticket: u64) -> Option<usize> {
        let waiters = self.waiters.lock();
        waiters
            .iter()
            .position(|waiter| waiter.ticket == ticket)
            .map(|index| index + 1)
    }

    #[cfg(test)]
    fn install_test_gate(&self, target_acquire: usize) -> AuthFinalizationTestGateHandle {
        let (entered_tx, entered_rx) = tokio::sync::watch::channel(0);
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);
        *self.test_gate.lock() = Some(AuthFinalizationTestGate {
            target_acquire,
            acquired_count: std::sync::atomic::AtomicUsize::new(0),
            entered_tx,
            release_rx,
        });
        AuthFinalizationTestGateHandle {
            entered_rx,
            release_tx,
        }
    }

    async fn wait_for_test_gate_if_needed(&self) {
        #[cfg(test)]
        {
            let release_rx = {
                let guard = self.test_gate.lock();
                let Some(gate) = guard.as_ref() else {
                    return;
                };
                let acquire_index = gate.acquired_count.fetch_add(1, Ordering::Relaxed) + 1;
                if acquire_index != gate.target_acquire {
                    return;
                }
                let _ = gate.entered_tx.send(acquire_index);
                gate.release_rx.clone()
            };
            let mut release_rx = release_rx;
            while !*release_rx.borrow() {
                if release_rx.changed().await.is_err() {
                    break;
                }
            }
        }
    }
}

struct AuthFinalizationTicket {
    queue: Arc<AuthFinalizationQueue>,
    ticket: u64,
}

impl Drop for AuthFinalizationTicket {
    fn drop(&mut self) {
        self.queue.remove_waiter(self.ticket);
    }
}

impl Drop for AuthFinalizationPermit {
    fn drop(&mut self) {
        self.queue.remove_waiter(self.ticket);
    }
}

impl AuthFinalizationPermit {
    pub(crate) fn authenticator(&self) -> &dyn Authenticator {
        self.queue.authenticator()
    }
}

fn auth_finalization_queue_message(
    session_id: ClientSessionIdentifier,
    position: usize,
) -> Message {
    let users_ahead = position.saturating_sub(1);

    Message::TextMessage(
        TextMessage {
            actor: None,
            session: vec![u32::from(session_id)],
            channel_id: Vec::new(),
            tree_id: Vec::new(),
            message: format!(
                "You're in the login queue. There are {users_ahead} users ahead of you."
            ),
        }
        .into(),
    )
}

fn should_send_auth_finalization_queue_notice(
    last_announced_position: &mut Option<usize>,
    position: usize,
) -> bool {
    if *last_announced_position == Some(position) {
        return false;
    }

    *last_announced_position = Some(position);
    true
}

fn is_pre_auth_passthrough_message(message: &Message) -> bool {
    matches!(message, Message::Ping(_))
}

fn is_pre_auth_dropped_message(message: &Message) -> bool {
    matches!(message, Message::UDPTunnel(_))
}

fn is_realtime_client_message(message: &Message) -> bool {
    matches!(message, Message::Ping(_) | Message::UDPTunnel(_))
}

fn authenticate_timeout_duration(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.max(MIN_AUTHENTICATE_TIMEOUT_MS))
}

fn map_handler_result(
    session_id: ClientSessionIdentifier,
    result: Result<(), MessageHandlerError>,
) -> Result<(), HandleIncomingConnectionError> {
    match result {
        Ok(()) => Ok(()),
        Err(MessageHandlerError::AuthRejection(rejection)) => {
            tracing::info!(
                session = u32::from(session_id),
                reason = rejection.reason(),
                "closing connection after auth rejection",
            );
            Err(HandleIncomingConnectionError::AuthRejected(rejection))
        }
        Err(err) => Err(HandleIncomingConnectionError::MessageHandlerFailed(err)),
    }
}

fn map_channel_replay_error(error: ChannelReplayError) -> HandleIncomingConnectionError {
    match error {
        ChannelReplayError::ClientWriteFailed(error) => {
            HandleIncomingConnectionError::ClientWriteFailed(error)
        }
    }
}

async fn activate_client_subscriptions(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    client_log_rx: &mut Option<ClientLogReceiver>,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> Result<(), HandleIncomingConnectionError> {
    if !client.is_authenticated() || client_log_rx.is_some() {
        return Ok(());
    }
    let server_id = client.server_id();
    let client_session_id = client.get_session_id();

    let post_auth_baseline = client.take_post_auth_baseline();
    let staged_channel_subscription = client.take_channel_state_subscription();
    let channel_snapshot_version = staged_channel_subscription
        .as_ref()
        .map(|(version, _)| *version)
        .unwrap_or_else(|| server.channels.current_version_in_server(&server_id));
    client
        .set_last_channel_version(channel_snapshot_version)
        .await;
    channel_tree_shadow.clear();
    if let Some(baseline) = post_auth_baseline {
        let (staged_session_shadow, staged_channel_tree_shadow, staged_user_visibility) =
            baseline.into_parts();
        session_channel_shadow.clear();
        session_channel_shadow.extend(staged_session_shadow);
        channel_tree_shadow.extend(staged_channel_tree_shadow);
        *user_visibility = staged_user_visibility;
    } else {
        tracing::warn!(
            server_id,
            session = u32::from(client_session_id),
            "post-auth baseline missing; rebuilding subscription shadows from repositories"
        );
        session_channel_shadow.clear();
        session_channel_shadow.extend(
            server
                .clients
                .get_all_clients_in_server(&server_id)
                .await
                .into_iter()
                .filter(|client| client.is_authenticated() && client.is_published())
                .map(|client| (client.get_session_id(), client.get_current_channel_id())),
        );
        channel_tree_shadow.extend(
            server
                .channels
                .get_all_in_server(&server_id)
                .await
                .into_iter()
                .map(|channel| channel.id),
        );
        if server.get_hide_users_without_traverse() {
            crate::client::visibility::initialize(
                server,
                client,
                user_visibility,
                session_channel_shadow,
            )
            .await;
        }
    }

    server
        .clients
        .publish_client_in_server(&server_id, client_session_id)
        .await;

    *client_log_rx = Some(
        client
            .take_client_state_subscription()
            .unwrap_or_else(|| server.clients.subscribe()),
    );
    *channel_log_rx = Some(
        staged_channel_subscription
            .map(|(_, rx)| rx)
            .unwrap_or_else(|| server.channels.subscribe()),
    );

    replay_client_log_entries_since(
        server,
        client,
        channel_tree_shadow,
        session_channel_shadow,
        user_visibility,
        &server_id,
        client_session_id,
        client.get_last_client_versions().await,
    )
    .await?;
    Ok(())
}

async fn replay_client_log_entries_since(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    server_id: &str,
    client_session_id: ClientSessionIdentifier,
    last_seen: HashMap<u16, u64>,
) -> Result<(), HandleIncomingConnectionError> {
    let (missed, new_versions) = server
        .clients
        .replay_entries_since_in_server_for_client(
            server_id,
            &last_seen,
            client.get_session_id(),
            client.client_instance_id(),
        )
        .await
        .map_err(|()| HandleIncomingConnectionError::ClientLogGapUnrecoverable)?;

    let mut out = Vec::new();
    for entry in missed {
        if should_skip_client_add_entry(
            &entry.op,
            client.get_session_id(),
            client.client_instance_id(),
            session_channel_shadow,
        ) {
            continue;
        }
        append_client_log_entry_messages(
            server,
            client,
            client_session_id,
            channel_tree_shadow,
            user_visibility,
            session_channel_shadow,
            server_id,
            &entry,
            &mut out,
        )
        .await?;
    }
    client
        .write_proto_message_batch(&out)
        .await
        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
    client.update_last_client_versions(&new_versions).await;
    Ok(())
}

async fn finish_handler_result(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    client_log_rx: &mut Option<ClientLogReceiver>,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    result: Result<(), MessageHandlerError>,
) -> Result<(), HandleIncomingConnectionError> {
    map_handler_result(client_session_id, result)?;
    activate_client_subscriptions(
        server,
        client,
        client_session_id,
        client_log_rx,
        channel_log_rx,
        channel_tree_shadow,
        session_channel_shadow,
        user_visibility,
    )
    .await
}

async fn finish_normal_client_message(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_log_rx: &mut Option<ClientLogReceiver>,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    message: Message,
) -> Result<(), HandleIncomingConnectionError> {
    let result = client.handle_message(server, message).await;
    finish_handler_result(
        server,
        client,
        client.get_session_id(),
        client_log_rx,
        channel_log_rx,
        channel_tree_shadow,
        session_channel_shadow,
        user_visibility,
        result,
    )
    .await?;
    client.touch_activity();
    Ok(())
}

async fn finish_deferred_client_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_log_rx: &mut Option<ClientLogReceiver>,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    messages: &mut VecDeque<Message>,
) -> Result<(), HandleIncomingConnectionError> {
    while let Some(message) = messages.pop_front() {
        finish_normal_client_message(
            server,
            client,
            client_log_rx,
            channel_log_rx,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            message,
        )
        .await?;
    }
    Ok(())
}

async fn continue_deferred_client_messages(
    handler_tasks: &mut JoinSet<Result<(), MessageHandlerError>>,
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_log_rx: &mut Option<ClientLogReceiver>,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    messages: &mut VecDeque<Message>,
    pre_auth_handler_in_flight: &mut bool,
) -> Result<(), HandleIncomingConnectionError> {
    if messages.is_empty() || *pre_auth_handler_in_flight {
        return Ok(());
    }

    if !client.is_authenticated() {
        if let Some(message) = messages.pop_front() {
            spawn_client_message_handler(handler_tasks, server, client, message);
            *pre_auth_handler_in_flight = true;
        }
        return Ok(());
    }

    finish_deferred_client_messages(
        server,
        client,
        client_log_rx,
        channel_log_rx,
        channel_tree_shadow,
        session_channel_shadow,
        user_visibility,
        messages,
    )
    .await
}

async fn finish_pre_auth_passthrough_message(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    message: Message,
) -> Result<(), HandleIncomingConnectionError> {
    let result = client.handle_message(server, message).await;
    map_handler_result(client.get_session_id(), result)?;
    client.touch_activity();
    Ok(())
}

fn spawn_client_message_handler(
    handler_tasks: &mut JoinSet<Result<(), MessageHandlerError>>,
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    message: Message,
) {
    let handler_server = Arc::clone(server);
    let handler_client = Arc::clone(client);
    handler_tasks.spawn(async move {
        handler_client
            .handle_message(&handler_server, message)
            .await
    });
}

fn is_acl_cache_flush_message(message: &Message) -> bool {
    matches!(message, Message::PermissionQuery(pq) if pq.flush == Some(true))
}

#[derive(Clone, Copy)]
enum PermissionInfoRefreshScope {
    All,
    HomeChannelDependent {
        old_channel_id: Option<u32>,
        new_channel_id: u32,
    },
}

fn permission_info_refresh_scope_for_delta(
    delta: &ClientGlobalStateDelta,
) -> Option<PermissionInfoRefreshScope> {
    if delta.user_id.is_some()
        || delta.groups.is_some()
        || delta.is_superuser.is_some()
        || delta.tokens.is_some()
    {
        Some(PermissionInfoRefreshScope::All)
    } else if let Some(new_channel_id) = delta.current_channel_id {
        Some(PermissionInfoRefreshScope::HomeChannelDependent {
            old_channel_id: None,
            new_channel_id,
        })
    } else {
        None
    }
}

fn permission_info_refresh_scope_for_entry(
    entry: &crate::client::state_log::ClientStateLogEntry,
    viewer_session_id: ClientSessionIdentifier,
    viewer_client_instance_id: ClientInstanceId,
) -> Option<PermissionInfoRefreshScope> {
    match &entry.op {
        ClientStateOperation::UpdateGlobalState {
            session_id,
            client_instance_id,
            delta,
            ..
        } if *session_id == viewer_session_id
            && *client_instance_id == viewer_client_instance_id =>
        {
            permission_info_refresh_scope_for_delta(delta)
        }
        _ => None,
    }
}

fn is_own_client_log_entry(
    op: &ClientStateOperation,
    session_id: ClientSessionIdentifier,
    client_instance_id: ClientInstanceId,
) -> bool {
    op.session_id() == Some(session_id) && op.client_instance_id() == client_instance_id
}

fn sorted_channel_ids(channel_ids: &HashSet<u32>) -> Vec<u32> {
    let mut channel_ids: Vec<_> = channel_ids.iter().copied().collect();
    channel_ids.sort_unstable();
    channel_ids
}

async fn permission_info_refresh_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    scope: PermissionInfoRefreshScope,
) -> Vec<Message> {
    match scope {
        PermissionInfoRefreshScope::All => {
            let mut messages =
                crate::channel_handler::build_channel_permission_query_refresh_messages(
                    server,
                    client,
                    server.get_channels(),
                )
                .await;
            if server.get_send_permission_info() {
                messages.extend(
                    crate::channel_handler::build_channel_permission_info_refresh_messages(
                        server,
                        client,
                        server.get_channels(),
                    )
                    .await,
                );
            }
            messages
        }
        PermissionInfoRefreshScope::HomeChannelDependent {
            old_channel_id,
            new_channel_id,
        } => {
            crate::channel_handler::build_home_channel_permission_info_refresh_messages(
                server,
                client,
                server.get_channels(),
                old_channel_id,
                new_channel_id,
            )
            .await
        }
    }
}

async fn write_projected_client_log_message_with_acl_refresh(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
) -> Result<(), HandleIncomingConnectionError> {
    write_projected_client_log_message_with_acl_refresh_scope(
        server,
        client,
        user_visibility,
        session_channel_shadow,
        server_id,
        message,
        PermissionInfoRefreshScope::All,
    )
    .await
}

async fn write_projected_client_log_message_with_acl_refresh_scope(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
    refresh_scope: PermissionInfoRefreshScope,
) -> Result<(), HandleIncomingConnectionError> {
    let mut out = crate::client::visibility::project_message_with_shadow(
        server,
        client,
        user_visibility,
        session_channel_shadow,
        server_id,
        message,
    )
    .await;

    let should_refresh_permissions = is_acl_cache_flush_message(message);
    if should_refresh_permissions {
        out.clear();
    }

    if should_refresh_permissions {
        for refresh in permission_info_refresh_messages(server, client, refresh_scope).await {
            out.extend(
                crate::client::visibility::project_message_with_shadow(
                    server,
                    client,
                    user_visibility,
                    session_channel_shadow,
                    server_id,
                    &refresh,
                )
                .await,
            );
        }
    }

    client
        .write_proto_message_batch(&out)
        .await
        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;

    Ok(())
}

async fn projected_client_log_messages_with_acl_refresh_scope(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    message: &Message,
    refresh_scope: PermissionInfoRefreshScope,
) -> Vec<Message> {
    let mut out = crate::client::visibility::project_message_with_shadow(
        server,
        client,
        user_visibility,
        session_channel_shadow,
        server_id,
        message,
    )
    .await;

    let should_refresh_permissions = is_acl_cache_flush_message(message);
    if should_refresh_permissions {
        out.clear();
    }

    if should_refresh_permissions {
        for refresh in permission_info_refresh_messages(server, client, refresh_scope).await {
            out.extend(
                crate::client::visibility::project_message_with_shadow(
                    server,
                    client,
                    user_visibility,
                    session_channel_shadow,
                    server_id,
                    &refresh,
                )
                .await,
            );
        }
    }

    out
}

async fn append_visibility_refresh_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    scope: crate::client::visibility::VisibilityRefreshScope,
    out: &mut Vec<Message>,
) {
    out.extend(
        crate::client::visibility::visibility_refresh_messages_with_shadow(
            server,
            client,
            user_visibility,
            session_channel_shadow,
            server_id,
            scope,
        )
        .await,
    );
}

async fn append_client_log_entry_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    user_visibility: &mut UserVisibilityState,
    session_channel_shadow: &mut SessionChannelShadow,
    server_id: &str,
    entry: &ClientStateLogEntry,
    out: &mut Vec<Message>,
) -> Result<(), HandleIncomingConnectionError> {
    if let Some(dep) = entry.channel_version_dep {
        let last_ch = client.get_last_channel_version().await;
        if last_ch < dep {
            client
                .write_proto_message_batch(out)
                .await
                .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
            out.clear();
            replay_channel_log_gap(
                server,
                client,
                &server.channels,
                channel_tree_shadow,
                session_channel_shadow,
                user_visibility,
                client_session_id,
                last_ch,
                dep + 1,
            )
            .await
            .map_err(map_channel_replay_error)?;
        }
    }

    let old_viewer_channel_id = session_channel_shadow
        .get(&client.get_session_id())
        .copied();
    let permission_refresh_scope = permission_info_refresh_scope_for_entry(
        entry,
        client.get_session_id(),
        client.client_instance_id(),
    )
    .map(|scope| match scope {
        PermissionInfoRefreshScope::HomeChannelDependent {
            old_channel_id: _,
            new_channel_id,
        } => PermissionInfoRefreshScope::HomeChannelDependent {
            old_channel_id: old_viewer_channel_id,
            new_channel_id,
        },
        scope => scope,
    })
    .unwrap_or(PermissionInfoRefreshScope::All);

    for msg in entry
        .messages_for_client(
            &server.clients,
            client.get_session_id(),
            client.client_instance_id(),
        )
        .await
    {
        out.extend(
            projected_client_log_messages_with_acl_refresh_scope(
                server,
                client,
                user_visibility,
                session_channel_shadow,
                server_id,
                &msg,
                permission_refresh_scope,
            )
            .await,
        );
    }

    let visibility_refresh_scope =
        crate::client::visibility::visibility_refresh_scope_for_client_log_entry(
            server,
            client,
            entry,
            old_viewer_channel_id,
        )
        .await;
    append_visibility_refresh_messages(
        server,
        client,
        user_visibility,
        session_channel_shadow,
        server_id,
        visibility_refresh_scope,
        out,
    )
    .await;
    Ok(())
}

async fn drain_outbound_message_queue(
    client: &Arc<Box<Client>>,
    first: ClientOutboundMessage,
    rx: &mut tokio::sync::mpsc::Receiver<ClientOutboundMessage>,
) -> Result<(), WriteProtoMessageError> {
    let mut messages = Vec::new();
    push_outbound_message(first, &mut messages);
    for _ in 1..CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT {
        match rx.try_recv() {
            Ok(message) => push_outbound_message(message, &mut messages),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    client.write_proto_message_batch_direct(&messages).await
}

fn push_outbound_message(message: ClientOutboundMessage, out: &mut Vec<Message>) {
    match message {
        ClientOutboundMessage::Single(message) => out.push(message),
        ClientOutboundMessage::Batch(messages) => out.extend(messages),
    }
}

fn spawn_native_client_writer_task(
    client: &Arc<Box<Client>>,
) -> Option<tokio::task::JoinHandle<Result<(), WriteProtoMessageError>>> {
    let span = client.tracing_span();
    let mut rx = match client.take_outbound_message_rx() {
        Some(rx) => rx,
        None => {
            span.in_scope(|| {
                tracing::warn!(
                    session = u32::from(client.get_session_id()),
                    "native client writer task already spawned"
                );
            });
            return None;
        }
    };
    let weak_client = Arc::downgrade(client);
    Some(tokio::spawn(
        async move {
            while let Some(message) = rx.recv().await {
                let Some(client) = weak_client.upgrade() else {
                    break;
                };
                drain_outbound_message_queue(&client, message, &mut rx).await?;
            }
            Ok(())
        }
        .instrument(span),
    ))
}

async fn process_channel_log_result(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    result: Option<Result<Arc<ChannelOperation>, tokio::sync::broadcast::error::RecvError>>,
) -> Result<ChannelLogReceiveOutcome, HandleIncomingConnectionError> {
    match result {
        Some(Ok(op)) => {
            if op.server_id != client.server_id() {
                return Ok(ChannelLogReceiveOutcome::Continue);
            }
            let last = client.get_last_channel_version().await;
            if op.version <= last && !op.is_root_name_config_update() {
                return Ok(ChannelLogReceiveOutcome::Continue);
            }
            if op.version > last {
                replay_channel_log_gap(
                    server,
                    client,
                    &server.channels,
                    channel_tree_shadow,
                    session_channel_shadow,
                    user_visibility,
                    client_session_id,
                    last,
                    op.version,
                )
                .await
                .map_err(map_channel_replay_error)?;
            }
            let last_after_replay = client.get_last_channel_version().await;
            if op.version <= last_after_replay && !op.is_root_name_config_update() {
                return Ok(ChannelLogReceiveOutcome::Continue);
            }

            let messages =
                crate::channel_handler::convert_channel_operation_to_messages_with_shadow(
                    server,
                    client,
                    &op,
                    &server.channels,
                    Some(session_channel_shadow),
                )
                .await;
            let mut outbound = Vec::new();
            for msg in messages {
                let projected = crate::client::visibility::project_message_with_shadow(
                    server,
                    client,
                    user_visibility,
                    session_channel_shadow,
                    &client.server_id(),
                    &msg,
                )
                .await;
                for msg in projected {
                    crate::channel_handler::sync_channel_tree_shadow(channel_tree_shadow, &msg);
                    outbound.push(msg);
                }
            }
            let refresh_scope =
                crate::client::visibility::visibility_refresh_scope_for_channel_operation(
                    server, &op,
                )
                .await;
            let projected = crate::client::visibility::visibility_refresh_messages_with_shadow(
                server,
                client,
                user_visibility,
                session_channel_shadow,
                &client.server_id(),
                refresh_scope,
            )
            .await;
            for msg in projected {
                crate::channel_handler::sync_channel_tree_shadow(channel_tree_shadow, &msg);
                outbound.push(msg);
            }
            client
                .write_proto_message_batch(&outbound)
                .await
                .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
            if op.version > last_after_replay {
                client.set_last_channel_version(op.version).await;
            }
            Ok(ChannelLogReceiveOutcome::Continue)
        }
        Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
            let last = client.get_last_channel_version().await;
            replay_channel_log_gap(
                server,
                client,
                &server.channels,
                channel_tree_shadow,
                session_channel_shadow,
                user_visibility,
                client_session_id,
                last,
                u64::MAX,
            )
            .await
            .map_err(map_channel_replay_error)?;
            Ok(ChannelLogReceiveOutcome::Continue)
        }
        Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
            Ok(ChannelLogReceiveOutcome::Closed)
        }
        None => Ok(ChannelLogReceiveOutcome::Continue),
    }
}

async fn drain_ready_channel_log_before_client_log(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    channel_log_rx: &mut Option<ChannelLogReceiver>,
) -> Result<ChannelLogReceiveOutcome, HandleIncomingConnectionError> {
    let Some(rx) = channel_log_rx.as_mut() else {
        return Ok(ChannelLogReceiveOutcome::Continue);
    };

    for _ in 0..CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT {
        let result = match rx.try_recv() {
            Ok(op) => Some(Ok(op)),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                Some(Err(tokio::sync::broadcast::error::RecvError::Closed))
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => Some(Err(
                tokio::sync::broadcast::error::RecvError::Lagged(skipped),
            )),
        };

        if process_channel_log_result(
            server,
            client,
            client_session_id,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            result,
        )
        .await?
            == ChannelLogReceiveOutcome::Closed
        {
            return Ok(ChannelLogReceiveOutcome::Closed);
        }
    }

    Ok(ChannelLogReceiveOutcome::Continue)
}

async fn process_client_log_broadcasts(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    first: Arc<ClientStateBroadcastPayload>,
    rx: &mut ClientLogReceiver,
) -> Result<(), HandleIncomingConnectionError> {
    let mut broadcasts = Vec::with_capacity(CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT);
    broadcasts.push(first);
    for _ in 1..CLIENT_CONNECTION_QUEUE_DRAIN_LIMIT {
        match rx.try_recv() {
            Ok(broadcast) => broadcasts.push(broadcast),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                replay_client_log_subscription_gap(
                    server,
                    client,
                    client_session_id,
                    channel_tree_shadow,
                    session_channel_shadow,
                    user_visibility,
                )
                .await?;
                return Ok(());
            }
        }
    }

    let client_server_id = client.server_id();
    let mut out = Vec::new();
    for broadcast in broadcasts {
        append_client_log_broadcast_messages(
            server,
            client,
            client_session_id,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            &client_server_id,
            broadcast,
            &mut out,
        )
        .await?;
    }

    client
        .write_proto_message_batch(&out)
        .await
        .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
    Ok(())
}

async fn append_client_log_broadcast_messages(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
    client_server_id: &str,
    broadcast: Arc<ClientStateBroadcastPayload>,
    out: &mut Vec<Message>,
) -> Result<(), HandleIncomingConnectionError> {
    tracing::trace!("Received client log broadcast: {:?}", broadcast);

    let entry = &broadcast.entry;
    if entry.op.server_id() != client_server_id {
        return Ok(());
    }
    let mut last_seen = client.get_last_client_versions().await;
    let mut last_for_node = last_seen.get(&entry.node_id).copied().unwrap_or(0);
    match broadcast.versions.get(&entry.node_id).copied() {
        Some(0) => {
            client.remove_last_client_version(entry.node_id).await;
            last_seen.remove(&entry.node_id);
            last_for_node = entry.version.saturating_sub(1);
        }
        Some(current) if current < last_for_node => {
            client.remove_last_client_version(entry.node_id).await;
            last_seen.remove(&entry.node_id);
            last_for_node = 0;
        }
        _ => {}
    }
    if entry.version <= last_for_node {
        return Ok(());
    }
    if entry.version > last_for_node + 1 {
        client
            .write_proto_message_batch(out)
            .await
            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
        out.clear();
        replay_client_log_entries_since(
            server,
            client,
            channel_tree_shadow,
            session_channel_shadow,
            user_visibility,
            client_server_id,
            client_session_id,
            last_seen,
        )
        .await?;
        return Ok(());
    }

    if should_skip_client_add_entry(
        &entry.op,
        client.get_session_id(),
        client.client_instance_id(),
        session_channel_shadow,
    ) {
        client
            .update_last_client_versions(&broadcast.versions)
            .await;
        return Ok(());
    }

    append_client_log_entry_messages(
        server,
        client,
        client_session_id,
        channel_tree_shadow,
        user_visibility,
        session_channel_shadow,
        client_server_id,
        entry,
        out,
    )
    .await?;
    client
        .update_last_client_versions(&broadcast.versions)
        .await;
    Ok(())
}

fn should_skip_client_add_entry(
    op: &ClientStateOperation,
    viewer_session_id: ClientSessionIdentifier,
    viewer_client_instance_id: crate::client::ClientInstanceId,
    session_channel_shadow: &SessionChannelShadow,
) -> bool {
    matches!(
        op,
        ClientStateOperation::AddClient {
            session_id,
            client_instance_id,
            ..
        } if *session_id == viewer_session_id && *client_instance_id == viewer_client_instance_id
            || session_channel_shadow.contains_key(session_id)
    )
}

async fn replay_client_log_subscription_gap(
    server: &Arc<Box<Server>>,
    client: &Arc<Box<Client>>,
    client_session_id: ClientSessionIdentifier,
    channel_tree_shadow: &mut ChannelTreeShadow,
    session_channel_shadow: &mut SessionChannelShadow,
    user_visibility: &mut UserVisibilityState,
) -> Result<(), HandleIncomingConnectionError> {
    let last_seen = client.get_last_client_versions().await;
    let server_id = client.server_id();
    replay_client_log_entries_since(
        server,
        client,
        channel_tree_shadow,
        session_channel_shadow,
        user_visibility,
        &server_id,
        client_session_id,
        last_seen,
    )
    .await
}

impl Server {
    pub async fn new<A: Authenticator>(
        config: Config,
        authenticator: A,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Self::new_with_extensions(config, authenticator, ServerExtensions::default()).await
    }

    pub async fn new_with_extensions<A: Authenticator>(
        config: Config,
        authenticator: A,
        extensions: ServerExtensions,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Self::new_with_reloadable_authenticator_and_extensions(
            config,
            ReloadableAuthenticator::fixed(authenticator),
            extensions,
        )
        .await
    }

    pub async fn new_with_reloadable_authenticator(
        config: Config,
        authenticator: ReloadableAuthenticator,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Self::new_with_reloadable_authenticator_and_extensions(
            config,
            authenticator,
            ServerExtensions::default(),
        )
        .await
    }

    pub async fn new_with_reloadable_authenticator_and_extensions(
        config: Config,
        authenticator: ReloadableAuthenticator,
        extensions: ServerExtensions,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Version::cache_server_os_info();

        let allowed_proxies = config
            .allowed_proxies
            .iter()
            .map(|proxy| AnyIpCidr::from_str(proxy))
            .collect::<Result<Vec<_>, _>>()?;
        validate_privacy_config(&config)?;

        let tls_acceptor = load_c2s_tls_acceptor(&config, &extensions)?;

        let entrypoints = bind_entrypoints(&config).await?;

        // ── Channel repository & blob stores ─────────────────────────────
        let node_id = config.local_node_id().map_err(std::io::Error::other)?;
        let client_log_max_entries = config.client_log_max_entries;
        let auth_finalization_concurrency = config.auth_finalization_concurrency.max(1);
        let channel_repo_tuning = ChannelRepoTuning::from(&config);
        let channel_root_config = ChannelRootConfig::from(&config);
        let (channels, channel_blobs, session_blobs, user_channel_cache, bans) = match &config
            .blob_storage_dir
        {
            Some(dir) => {
                let ch_repo =
                    ChannelRepository::open(node_id, dir, channel_root_config, channel_repo_tuning)
                        .await?;
                let ch_blobs = Arc::new(ChannelBlobStore::open(dir).await?);
                let s_blobs = Arc::new(SessionBlobStore::open(dir).await?);
                let user_channel_cache = UserChannelCache::open(dir).await?;
                let ban_repo = crate::ban_repository::BanRepository::open(node_id, dir).await?;
                (ch_repo, ch_blobs, s_blobs, user_channel_cache, ban_repo)
            }
            None => {
                // In-memory mode: use a temp dir for blob stores so the
                // code paths are uniform; blobs won't survive restarts.
                let tmp = std::env::temp_dir().join("shitspeak-blobs");
                let ch_repo = ChannelRepository::new_in_memory(
                    node_id,
                    channel_root_config,
                    channel_repo_tuning,
                );
                let ch_blobs = Arc::new(ChannelBlobStore::open(&tmp).await?);
                let s_blobs = Arc::new(SessionBlobStore::open(&tmp).await?);
                let user_channel_cache = UserChannelCache::new_in_memory();
                let ban_repo = crate::ban_repository::BanRepository::new_in_memory(node_id);
                (ch_repo, ch_blobs, s_blobs, user_channel_cache, ban_repo)
            }
        };

        let config = Arc::new(StdRwLock::new(config));
        let s2s_manager = Arc::new(S2SManager::initialize(
            &config.read().expect("Config RwLock poisoned"),
        ));
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(());

        let server = Arc::new(Box::new(Server {
            node_identifier: node_id,
            allowed_proxies,
            tls_acceptor: ParkingRwLock::new(tls_acceptor),
            extensions,
            entrypoints: Arc::new(ParkingRwLock::new(entrypoints)),
            entrypoint_runtime: Mutex::new(None),
            entrypoint_reload_lock: tokio::sync::Mutex::new(()),
            clients: Arc::new(ClientRepository::new(node_id, client_log_max_entries)),
            channels,
            auth_finalization_queue: Arc::new(AuthFinalizationQueue::new(
                auth_finalization_concurrency,
                authenticator,
            )),
            crypt_setup_semaphore: Arc::new(tokio::sync::Semaphore::new(
                auth_finalization_concurrency,
            )),
            channel_blobs,
            session_blobs,
            user_channel_cache,
            bans,
            codec_info: Mutex::new(CodecInfo::default()),
            config: Arc::clone(&config),
            context_actions: Arc::new(crate::context_action::ContextActionRegistry::new()),
            s2s_manager,
            geoip_resolver: ParkingRwLock::new(Arc::new(GeoIpResolver::new(
                config.read().expect("Config RwLock poisoned").geoip.clone(),
            ))),
            shutdown_tx,
        }));

        // Wire cross-repo causal notification: ChannelRepository notifies
        // ClientRepository to drain pending ops after remote channel ops.
        server
            .channels
            .set_client_repo(server.clients.clone())
            .await;

        Ok(server)
    }

    /// Read the current config (acquires a read lock).
    pub fn read_config(&self) -> std::sync::RwLockReadGuard<'_, Config> {
        self.config.read().expect("Config RwLock poisoned")
    }

    /// Local TCP listen address. Useful for tests that bind to `127.0.0.1:0`.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        let entrypoints = self.entrypoints.read();
        entrypoints
            .tcp_listeners
            .first()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no TCP listeners"))?
            .listener
            .local_addr()
    }

    /// Local UDP listen address. Useful for tests that bind to `127.0.0.1:0`.
    pub fn local_udp_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        let entrypoints = self.entrypoints.read();
        entrypoints
            .udp_sockets
            .first()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no UDP sockets"))?
            .local_addr()
    }

    pub fn shutdown_receiver(&self) -> tokio::sync::watch::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub async fn lookup_ip_geo_metadata(&self, ip: std::net::IpAddr) -> Option<IpGeoMetadata> {
        let resolver = self.geoip_resolver.read().clone();
        resolver.lookup_ip_metadata(ip).await
    }

    pub fn authenticator_watch_paths(&self) -> Vec<PathBuf> {
        let config = self.read_config();
        let mut paths = Vec::new();
        if let Some(path) = config.authenticator.wasm().path() {
            paths.push(path.clone());
        }
        if let Some(path) = config.authenticator.exec().command() {
            paths.push(path.clone());
        }
        paths
    }

    pub fn c2s_tls_identity_paths(&self) -> (PathBuf, PathBuf) {
        let config = self.read_config();
        (
            PathBuf::from(&config.cert_path),
            PathBuf::from(&config.key_path),
        )
    }

    fn replace_c2s_tls_acceptor(&self, tls_acceptor: TlsAcceptor) {
        *self.tls_acceptor.write() = tls_acceptor;
    }

    fn reload_c2s_tls_identity(
        &self,
        new_config: &Config,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tls_acceptor = load_c2s_tls_acceptor(new_config, &self.extensions)?;
        self.replace_c2s_tls_acceptor(tls_acceptor);
        Ok(())
    }

    pub fn authenticator_arc(&self) -> Arc<dyn Authenticator> {
        self.auth_finalization_queue.authenticator_arc()
    }

    pub async fn run(self: &Arc<Box<Self>>) -> Result<(), Box<dyn std::error::Error>> {
        let mut shutdown_rx = self.shutdown_receiver();
        let listen_addrs: Vec<String> = {
            let entrypoints = self.entrypoints.read();
            entrypoints
                .tcp_listeners
                .iter()
                .filter_map(|entry| entry.listener.local_addr().ok())
                .map(|addr| addr.to_string())
                .collect()
        };
        tracing::info!("Server is running on {}", listen_addrs.join(", "));
        self.s2s_manager.log_startup_summary();

        // Snapshot startup-only config values (cannot be hot-reloaded).
        let udp_channel_size = self.read_config().udp_channel_size;
        let udp_voice_enabled = self.read_config().udp_voice_enabled;
        let udp_ping_enabled = self.read_config().udp_ping_enabled;
        let idle_timeout_secs = self.read_config().client_idle_timeout_secs;
        let pending_delete_timeout_ms = self.read_config().pending_delete_timeout_ms;

        // Bounded channel shared between UDP drain and processing tasks.
        let (udp_in, udp_out) = tokio::sync::mpsc::channel::<UdpPacket>(udp_channel_size);

        // Internal shutdown channel: used to signal all spawned tasks regardless
        // of whether shutdown originated from the external signal or a task dying.
        let (internal_tx, internal_rx) = tokio::sync::watch::channel(());

        {
            let mut runtime = self.entrypoint_runtime.lock();
            *runtime = Some(EntrypointRuntime {
                udp_in: udp_in.clone(),
                udp_voice_enabled,
                udp_ping_enabled,
                shutdown: internal_rx.clone(),
            });
        }
        let mut udp_process = Self::spawn_udp_process(
            Arc::clone(self),
            udp_out,
            udp_ping_enabled,
            internal_rx.clone(),
        );
        self.spawn_entrypoint_tasks_for_existing_bindings(&udp_in, &internal_rx);
        let mut idle_reaper =
            Self::spawn_idle_reaper(Arc::clone(self), idle_timeout_secs, internal_rx.clone());
        let mut pending_delete_watchdog = Self::spawn_pending_delete_watchdog(
            Arc::clone(self),
            pending_delete_timeout_ms,
            internal_rx.clone(),
        );
        let mut extension_tasks = JoinSet::<()>::new();
        self.extensions
            .spawn_tasks(Arc::clone(self), internal_rx.clone(), &mut extension_tasks)?;
        let s2s_task = Arc::clone(&self.s2s_manager)
            .spawn_runtime_task(Arc::downgrade(self), internal_rx.clone());
        let metrics_source: Arc<dyn crate::observability::S2sMetricsSource> =
            Arc::new(crate::observability::ServerMetricsSource::new(
                self.s2s_manager.clone(),
                self.clients.clone(),
                self.channels.clone(),
            ));
        let observability_metrics_task = {
            let metrics = self.read_config().observability.metrics.clone();
            if metrics.enabled {
                metrics.listen.and_then(|listen| {
                    match crate::observability::spawn_metrics_server(
                        listen,
                        metrics.path.clone(),
                        metrics_source.clone(),
                        internal_rx.clone(),
                    ) {
                        Ok(task) => Some(task),
                        Err(error) => {
                            tracing::warn!(
                                %listen,
                                %error,
                                "observability metrics HTTP server startup failed"
                            );
                            None
                        }
                    }
                })
            } else {
                None
            }
        };
        let observability_remote_write_task = {
            let config = self
                .read_config()
                .observability
                .metrics
                .remote_write
                .clone();
            crate::observability::spawn_remote_write(config, metrics_source, internal_rx.clone())
        };

        // Public server registration (periodic HTTP POST to registry).
        // This task is optional and may exit early when registration is disabled;
        // it must never terminate the main server loop.
        let register_task =
            crate::register::spawn_register_task(Arc::clone(self), internal_rx.clone());

        // Wait for any task to finish (error) or for the caller to request
        // shutdown by sending on the shared watch channel.
        tokio::select! {
            result = &mut udp_process => { let _ = result; }
            result = &mut idle_reaper => { let _ = result; }
            result = &mut pending_delete_watchdog => { let _ = result; }
            result = extension_tasks.join_next(), if !extension_tasks.is_empty() => { let _ = result; }
            _ = shutdown_rx.changed() => {
                tracing::info!("Shutdown signal received.");
            }
        }

        // Ensure every spawned runtime task observes shutdown before joining.
        let _ = internal_tx.send(());

        let _ = udp_process.await;
        let _ = idle_reaper.await;
        let _ = pending_delete_watchdog.await;
        while extension_tasks.join_next().await.is_some() {}
        s2s_task.join().await;
        if let Some(task) = observability_metrics_task {
            let _ = task.await;
        }
        if let Some(task) = observability_remote_write_task {
            let _ = task.await;
        }
        let _ = register_task.await;

        Ok(())
    }

    /// Spawn the UDP drain task: receive packets as fast as possible and
    /// push voice packets into the channel.  Ping packets are handled
    /// directly (responded to immediately).
    fn spawn_udp_drain(
        server: Arc<Box<Self>>,
        socket: Arc<tokio::net::UdpSocket>,
        tx: tokio::sync::mpsc::Sender<UdpPacket>,
        voice_enabled: bool,
        ping_enabled: bool,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = BytesMut::with_capacity(MTU);
            let local_addr = socket
                .local_addr()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            tracing::info!("UDP drain started, listening on {}", local_addr);
            loop {
                buf.clear();
                buf.reserve(MTU);
                let (len, src_addr) = tokio::select! {
                    result = socket.recv_buf_from(&mut buf) => match result {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("UDP recv error: {e}");
                            continue;
                        }
                    },
                    _ = shutdown.changed() => break,
                };

                if len <= 1 {
                    // Empty packages or packages consisting only of the header byte are invalid
                    continue;
                }

                tracing::trace!("UDP received {} bytes from {}", len, src_addr);

                if ping_enabled {
                    match crate::voice::ping::PingRequest::decode(&buf) {
                        Ok(ping) => {
                            tracing::debug!(
                                "UDP ping from {}: timestamp={}, format={}",
                                src_addr,
                                ping.timestamp,
                                ping.format
                            );
                            let status_server_id =
                                server.udp_ping_status_server_id_for_port(local_addr.port());
                            let reply =
                                match Self::build_ping_response(&server, &ping, &status_server_id)
                                    .await
                                {
                                    Ok(r) => r,
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to build UDP ping response for {}: {e}",
                                            src_addr
                                        );
                                        continue;
                                    }
                                };
                            match socket.send_to(&reply, src_addr).await {
                                Ok(sent) => tracing::trace!(
                                    "UDP ping reply sent to {}: {} bytes",
                                    src_addr,
                                    sent
                                ),
                                Err(e) => {
                                    tracing::warn!("UDP ping reply failed to {}: {e}", src_addr)
                                }
                            }
                            continue;
                        }
                        Err(crate::voice::codec::DecodeError::NotPing) => {
                            // Not a ping packet, continue with normal processing
                        }
                        Err(e) => {
                            tracing::trace!("UDP packet decode failed from {}: {e}", src_addr);
                            continue;
                        }
                    }
                }

                if voice_enabled {
                    let packet = buf.split().freeze();
                    match tx.try_send((packet, src_addr, local_addr)) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                "UDP processing channel is full, dropping packet from {}",
                                src_addr
                            );
                        }
                        Err(e) => {
                            tracing::warn!("UDP processing channel error for {}: {e}", src_addr);
                        }
                    }
                }
            }
            tracing::info!("UDP drain stopped");
        })
    }

    /// Spawn the UDP processing task: decrypt, parse, and route voice
    /// packets from the channel.  Ping packets are handled directly.
    fn spawn_udp_process(
        server: Arc<Box<Self>>,
        mut rx: tokio::sync::mpsc::Receiver<UdpPacket>,
        ping_enabled: bool,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let (packet, src_addr, local_addr) = tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(m) => m,
                        None => break,
                    },
                    _ = shutdown.changed() => break,
                };
                // Try address-based match first.  If the cached entry exists but
                // decrypt fails (stale NAT binding, crypt state re-keyed, etc.)
                // the binding is removed and we fall through to IP-based candidate
                // probing so the packet is not silently dropped.
                let mut decrypted_from_match: Option<BytesMut> = None;
                let mut matched_via_ip_fallback = false;

                let client = {
                    let address_match = server
                        .clients
                        .get_client_by_udp_endpoint(local_addr, src_addr)
                        .await;
                    let mut found = None;

                    if let Some(c) = address_match {
                        let decrypt_result: Option<Result<BytesMut, _>> = {
                            let mut crypt = c.crypt_state();
                            crypt.as_mut().map(|state| {
                                let mut dec = BytesMut::new();
                                state.decrypt(&mut dec, &packet).map(|_| dec)
                            })
                        };

                        match decrypt_result {
                            Some(Ok(dec)) => {
                                tracing::trace!(
                                    "UDP client matched by address: {} -> session {:?}",
                                    src_addr,
                                    c.get_session_id()
                                );
                                decrypted_from_match = Some(dec);
                                found = Some(c);
                            }
                            Some(Err(e)) => {
                                tracing::trace!(
                                    "UDP address-match decrypt failed for {:?} from {}: {:?}, removing stale binding",
                                    c.get_session_id(),
                                    src_addr,
                                    e
                                );
                                server
                                    .clients
                                    .unbind_client_udp_endpoint(local_addr, src_addr);
                            }
                            None => {
                                tracing::trace!(
                                    "UDP address-matched client {:?} has no crypt state, removing stale binding",
                                    c.get_session_id()
                                );
                                server
                                    .clients
                                    .unbind_client_udp_endpoint(local_addr, src_addr);
                            }
                        }
                    }

                    if found.is_none() {
                        let candidates = server.clients.get_clients_by_ip(&src_addr.ip()).await;
                        let mut matched = None;
                        for c in &candidates {
                            let decrypted = {
                                let mut crypt = c.crypt_state();
                                match crypt.as_mut() {
                                    Some(state) => {
                                        let mut decrypted = BytesMut::new();
                                        match state.decrypt(&mut decrypted, &packet) {
                                            Ok(()) => {
                                                tracing::trace!(
                                                    "UDP packet from {} successfully decrypted with client {:?} during IP fallback",
                                                    src_addr,
                                                    c.get_session_id()
                                                );
                                                Some(decrypted)
                                            }
                                            Err(e) => {
                                                tracing::trace!(
                                                    "UDP packet from {} failed to decrypt with client {:?} during IP fallback: {:?}",
                                                    src_addr,
                                                    c.get_session_id(),
                                                    e
                                                );
                                                None
                                            }
                                        }
                                    }
                                    None => {
                                        tracing::trace!(
                                            "UDP client {:?} has no crypt state yet, skipping for IP fallback",
                                            c.get_session_id()
                                        );
                                        None
                                    }
                                }
                            };
                            if let Some(decrypted) = decrypted {
                                matched = Some(c.clone());
                                decrypted_from_match = Some(decrypted);
                                matched_via_ip_fallback = true;
                                break;
                            }
                        }

                        tracing::trace!(
                            "UDP client {} matched by IP fallback: candidates={}, matched={:?}",
                            src_addr,
                            candidates.len(),
                            matched.as_ref().map(|c| c.get_session_id()),
                        );
                        found = matched;
                    }

                    found
                };

                let Some(client) = client else { continue };

                client.record_udp_packet(packet.len()).await;
                client.touch_activity();

                // A valid encrypted UDP packet indicates UDP path is working.
                client.set_prefer_tcp_tunnel(false);

                if matched_via_ip_fallback {
                    tracing::trace!(
                        "Binding UDP address {} to client {:?} after successful IP fallback match",
                        src_addr,
                        client.get_session_id()
                    );

                    server
                        .clients
                        .bind_client_udp_endpoint_in_server(
                            &client.server_id(),
                            client.get_session_id(),
                            Some(local_addr),
                            src_addr,
                        )
                        .await;
                }

                // Packet was already decrypted during client matching.
                let Some(decrypted) = decrypted_from_match else {
                    continue;
                };

                // After decryption, check if this is a ping or audio packet.
                match crate::voice::codec::IncomingUdpPacket::decode(
                    &decrypted,
                    Some(client.get_session_id()),
                ) {
                    Ok(crate::voice::codec::IncomingUdpPacket::Ping(ping)) => {
                        tracing::trace!(
                            "UDP ping from {}: timestamp={}, format={}",
                            src_addr,
                            ping.timestamp,
                            ping.format
                        );
                        tracing::debug!("UDP ping from {}: timestamp={}", src_addr, ping.timestamp);
                        let cleartext = match ping.encode_authenticated_echo() {
                            Ok(reply) => reply,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to encode authenticated UDP ping response for {}: {e}",
                                    src_addr
                                );
                                continue;
                            }
                        };
                        let encrypted = {
                            let mut crypt = client.crypt_state();
                            let Some(state) = crypt.as_mut() else {
                                tracing::warn!(
                                    "no crypt state available for authenticated UDP ping reply to {}",
                                    src_addr
                                );
                                continue;
                            };
                            let mut encrypted = vec![0u8; cleartext.len() + state.overhead()];
                            if let Err(e) = state.encrypt(&mut encrypted, &cleartext) {
                                tracing::warn!(
                                    "Failed to encrypt authenticated UDP ping response for {}: {:?}",
                                    src_addr,
                                    e
                                );
                                continue;
                            }
                            encrypted
                        };
                        let socket = server
                            .udp_socket_for_local_addr(local_addr)
                            .or_else(|| server.default_udp_socket());
                        let Some(socket) = socket else {
                            tracing::warn!("no UDP socket available for ping reply");
                            continue;
                        };
                        match socket.send_to(&encrypted, src_addr).await {
                            Ok(sent) => tracing::trace!(
                                "authenticated UDP ping reply sent to {}: {} bytes",
                                src_addr,
                                sent
                            ),
                            Err(e) => tracing::warn!("UDP ping reply failed to {}: {e}", src_addr),
                        }
                        continue;
                    }
                    Ok(crate::voice::codec::IncomingUdpPacket::Audio(decoded_audio)) => {
                        if !client.is_authenticated() {
                            tracing::trace!(
                                "UDP audio packet from {} matched unauthenticated client {:?}; dropping",
                                src_addr,
                                client.get_session_id()
                            );
                            continue;
                        }
                        tracing::trace!(
                            "UDP audio packet from {}: sender_session={:?}, frame_number={}, format={:?}, payload_len={}",
                            src_addr,
                            decoded_audio.sender_session,
                            decoded_audio.frame_number,
                            decoded_audio.format,
                            decoded_audio.audio_payload.len()
                        );
                        client.push_voice_routing(decoded_audio);
                    }
                    Err(e) => {
                        tracing::trace!("UDP packet decode failed from {}: {e}", src_addr);
                        continue;
                    }
                }
            }
        })
    }

    fn udp_socket_for_local_addr(
        &self,
        local_addr: SocketAddr,
    ) -> Option<Arc<tokio::net::UdpSocket>> {
        self.entrypoints
            .read()
            .udp_socket_by_port
            .get(&local_addr.port())
            .cloned()
    }

    pub fn udp_socket_for_client_addr(
        &self,
        local_addr: SocketAddr,
    ) -> Option<Arc<tokio::net::UdpSocket>> {
        self.udp_socket_for_local_addr(local_addr)
            .or_else(|| self.default_udp_socket())
    }

    pub fn udp_socket_for_client(&self, client: &Client) -> Option<Arc<tokio::net::UdpSocket>> {
        self.udp_socket_for_client_addr(client.get_local_address())
    }

    fn default_udp_socket(&self) -> Option<Arc<tokio::net::UdpSocket>> {
        self.entrypoints.read().udp_sockets.first().cloned()
    }

    /// Spawn the TCP accept loop for one listener.
    fn spawn_tcp_accept(
        server: Arc<Box<Self>>,
        listener: Arc<tokio::net::TcpListener>,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let local_addr = listener
                .local_addr()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            tracing::info!("TCP accept started, listening on {}", local_addr);
            loop {
                let (tcp_stream, remote_addr) = tokio::select! {
                    result = listener.accept() => match result {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("TCP accept error: {e}");
                            continue;
                        }
                    },
                    _ = shutdown.changed() => break,
                };
                let conn_server = Arc::clone(&server);
                let provisional_server_id =
                    conn_server.provisional_server_id_for_port(local_addr.port());
                tokio::spawn(async move {
                    let _ = conn_server
                        .handle_incoming_connection(tcp_stream, remote_addr, provisional_server_id)
                        .await;
                });
            }
            tracing::info!("TCP accept stopped for {}", local_addr);
        })
    }

    fn provisional_server_id_for_port(&self, port: u16) -> String {
        self.entrypoints
            .read()
            .server_id_by_port
            .get(&port)
            .cloned()
            .unwrap_or_else(default_server_id)
    }

    fn udp_ping_status_server_id_for_port(&self, port: u16) -> String {
        self.entrypoints
            .read()
            .udp_ping_status_server_id_by_port
            .get(&port)
            .cloned()
            .unwrap_or_else(default_server_id)
    }

    fn spawn_entrypoint_tasks_for_existing_bindings(
        self: &Arc<Box<Self>>,
        udp_in: &tokio::sync::mpsc::Sender<UdpPacket>,
        shutdown: &tokio::sync::watch::Receiver<()>,
    ) {
        let (listeners, sockets) = {
            let entrypoints = self.entrypoints.read();
            (
                entrypoints.tcp_listeners.clone(),
                entrypoints.udp_sockets.clone(),
            )
        };

        for entrypoint in listeners {
            Self::spawn_tcp_accept(Arc::clone(self), entrypoint.listener, shutdown.clone());
        }
        for socket in sockets {
            Self::spawn_udp_drain(
                Arc::clone(self),
                socket,
                udp_in.clone(),
                self.read_config().udp_voice_enabled,
                self.read_config().udp_ping_enabled,
                shutdown.clone(),
            );
        }
    }

    fn spawn_entrypoint_tasks_for_new_binding(
        self: &Arc<Box<Self>>,
        listener: Arc<tokio::net::TcpListener>,
        udp_socket: Arc<tokio::net::UdpSocket>,
    ) {
        let Some(runtime) = self.entrypoint_runtime.lock().clone() else {
            return;
        };

        Self::spawn_tcp_accept(Arc::clone(self), listener, runtime.shutdown.clone());
        Self::spawn_udp_drain(
            Arc::clone(self),
            udp_socket,
            runtime.udp_in,
            runtime.udp_voice_enabled,
            runtime.udp_ping_enabled,
            runtime.shutdown,
        );
    }

    async fn apply_entrypoint_config(
        self: &Arc<Box<Self>>,
        new_config: &Config,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _reload_guard = self.entrypoint_reload_lock.lock().await;
        let (server_id_by_sni, listen_specs) = entrypoint_config_routes(new_config)?;
        let default_port = self.entrypoints.read().default_port;

        let mut new_bindings = Vec::new();
        let mut udp_ping_status_updates = Vec::new();
        for spec in listen_specs {
            let EntrypointListenSpec {
                address,
                server_id,
                udp_ping_status_server_id,
            } = spec;
            if address.port() == default_port {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "server entrypoint for {server_id} reuses the default TCP/UDP port {default_port}"
                    ),
                )
                .into());
            }

            if address.port() != 0 {
                let existing = self
                    .entrypoints
                    .read()
                    .server_id_by_port
                    .get(&address.port())
                    .cloned();
                if let Some(existing) = existing {
                    if existing != server_id {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "TCP/UDP port {} is already mapped to {}, cannot remap to {} during hot reload",
                                address.port(),
                                existing,
                                server_id
                            ),
                        )
                        .into());
                    }
                    udp_ping_status_updates.push((address.port(), udp_ping_status_server_id));
                    continue;
                }
            }

            let (listener, udp_socket) = bind_entrypoint_socket_pair(address).await?;
            let port = listener.local_addr()?.port();
            if port == default_port {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "server entrypoint for {server_id} reuses the default TCP/UDP port {port}"
                    ),
                )
                .into());
            }

            {
                let entrypoints = self.entrypoints.read();
                if let Some(existing) = entrypoints.server_id_by_port.get(&port) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "TCP/UDP port {port} is already mapped to {existing}, cannot map to {server_id} during hot reload"
                        ),
                    )
                    .into());
                }
            }

            new_bindings.push((
                server_id,
                udp_ping_status_server_id,
                Arc::new(listener),
                udp_socket,
                port,
            ));
        }

        {
            let mut entrypoints = self.entrypoints.write();
            entrypoints.server_id_by_sni = server_id_by_sni;
            for (port, udp_ping_status_server_id) in udp_ping_status_updates {
                entrypoints
                    .udp_ping_status_server_id_by_port
                    .insert(port, udp_ping_status_server_id);
            }
            for (server_id, udp_ping_status_server_id, listener, udp_socket, port) in &new_bindings
            {
                entrypoints
                    .server_id_by_port
                    .insert(*port, server_id.clone());
                entrypoints
                    .udp_ping_status_server_id_by_port
                    .insert(*port, udp_ping_status_server_id.clone());
                entrypoints
                    .udp_socket_by_port
                    .insert(*port, Arc::clone(udp_socket));
                entrypoints.udp_sockets.push(Arc::clone(udp_socket));
                entrypoints.tcp_listeners.push(ServerTcpListener {
                    listener: Arc::clone(listener),
                });
            }
        }

        for (server_id, _udp_ping_status_server_id, listener, udp_socket, port) in new_bindings {
            tracing::info!(
                "config reload: added client entrypoint {} for server_id {}",
                port,
                server_id
            );
            self.spawn_entrypoint_tasks_for_new_binding(listener, udp_socket);
        }

        Ok(())
    }

    /// Spawn a periodic task that disconnects local clients who haven't sent a
    /// ping within `timeout_secs`.
    fn spawn_idle_reaper(
        server: Arc<Box<Self>>,
        timeout_secs: u64,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let interval = std::time::Duration::from_secs((timeout_secs / 2).max(1));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = shutdown.changed() => break,
                }

                server
                    .disconnect_idle_local_clients(chrono::Utc::now(), timeout_secs)
                    .await;
            }
        })
    }

    async fn disconnect_idle_local_clients(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        timeout_secs: u64,
    ) {
        let timeout = chrono::Duration::seconds(timeout_secs as i64);
        let clients = self.clients.get_local_clients().await;

        for client in &clients {
            let last_ping = client.get_last_ping().await;
            if now - last_ping > timeout {
                let sid = client.get_session_id();
                let server_id = client.server_id();
                let old_channel_id = client.get_current_channel_id();
                tracing::info!(
                    "Disconnecting idle local client {:?} (last ping: {}, timeout: {}s)",
                    sid,
                    last_ping,
                    timeout_secs,
                );
                self.clients
                    .remove_client_instance_in_server(&server_id, sid, client.client_instance_id())
                    .await;
                if let Err(e) = client.disconnect().await {
                    tracing::debug!(
                        error = %e,
                        session = u32::from(sid),
                        "failed to disconnect idle client",
                    );
                }
                crate::client::handlers::temp_channel::reap_if_empty_temporary_on_server(
                    self,
                    &server_id,
                    old_channel_id,
                )
                .await;
            }
        }
    }

    /// Spawn a periodic task that rolls back stale pending channel deletes.
    fn spawn_pending_delete_watchdog(
        server: Arc<Box<Self>>,
        timeout_ms: u64,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let timeout_ms = timeout_ms.max(1);
        let interval = std::time::Duration::from_millis((timeout_ms / 2).max(100));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = shutdown.changed() => break,
                }

                let server_ids = server.channels.known_server_ids();
                for server_id in server_ids {
                    let expired = server
                        .channels
                        .expired_pending_deletes_in_server(&server_id, timeout_ms as i64)
                        .await;
                    for (channel_id, nonce) in expired {
                        let op = crate::channel_repository::ChannelOp::CancelPendingDelete {
                            id: channel_id,
                            nonce,
                        };
                        if server
                            .s2s_manager()
                            .propose_channel_op(Some(&server_id), op)
                            .await
                            .should_apply_locally()
                        {
                            if let Err(e) = server
                                .channels
                                .cancel_pending_delete_in_server(&server_id, channel_id, nonce)
                                .await
                            {
                                tracing::trace!(
                                    server_id,
                                    channel_id,
                                    nonce,
                                    error = ?e,
                                    "pending delete rollback failed"
                                );
                            }
                        }
                    }
                }
            }
        })
    }

    pub async fn handle_incoming_connection(
        self: &Arc<Box<Self>>,
        mut tcp_stream: tokio::net::TcpStream,
        remote_addr: std::net::SocketAddr,
        provisional_server_id: String,
    ) -> Result<(), HandleIncomingConnectionError> {
        tracing::info!(
            %remote_addr,
            provisional_server_id,
            "TCP connection established"
        );
        let proxy_connection = if self
            .allowed_proxies
            .iter()
            .any(|proxy| proxy.contains(&remote_addr.ip()))
        {
            consume_proxy_protocol_connection_info(&mut tcp_stream).await?
        } else {
            None
        };
        let uses_proxy_protocol = proxy_connection.is_some();
        let client_addr = proxy_connection
            .and_then(|info| info.client_address())
            .map(|addr| SocketAddr::new(addr.ip(), addr.port()))
            .unwrap_or(remote_addr);
        let real_ip = client_addr.ip();

        let local_addr = tcp_stream.local_addr()?;
        tracing::info!(
            %remote_addr,
            %client_addr,
            %local_addr,
            uses_proxy_protocol,
            "TLS handshake starting"
        );
        let tls_ja4 = crate::tls_fingerprint::peek_tls_ja4(&tcp_stream).await?;
        let tls_acceptor = self.tls_acceptor.read().clone();
        let tls_stream = tls_acceptor.accept(tcp_stream).await?;
        let server_id = self.resolve_tls_server_id(&provisional_server_id, local_addr, &tls_stream);
        tracing::info!(
            %remote_addr,
            %client_addr,
            %local_addr,
            server_id,
            alpn = ?tls_stream.get_ref().1.alpn_protocol().map(String::from_utf8_lossy),
            tls_ja4 = ?tls_ja4,
            "TLS handshake completed"
        );
        let negotiated_alpn = tls_stream.get_ref().1.alpn_protocol().map(Vec::from);
        if let Some(protocol) = negotiated_alpn.as_deref() {
            if protocol == ALPN_MUMBLE {
                // Continue with the native Mumble path below.
            } else if self.extensions.handles_c2s_alpn_protocol(protocol) {
                let info = AlpnConnectionInfo::new(
                    real_ip,
                    client_addr,
                    local_addr,
                    server_id,
                    tls_ja4,
                    uses_proxy_protocol,
                );
                if let Some(handler) = self.extensions.handle_c2s_alpn_stream(
                    Arc::clone(self),
                    protocol,
                    tls_stream,
                    info,
                ) {
                    handler.await?;
                } else {
                    tracing::warn!(
                        protocol = %String::from_utf8_lossy(protocol),
                        "ALPN protocol was registered but no handler accepted the stream"
                    );
                }
                return Ok(());
            } else {
                tracing::warn!(
                    protocol = %String::from_utf8_lossy(protocol),
                    "unsupported ALPN protocol, closing connection"
                );
                return Ok(());
            }
        }

        self.handle_native_mumble_tls_connection(
            tls_stream,
            real_ip,
            client_addr,
            local_addr,
            server_id,
            tls_ja4,
            uses_proxy_protocol,
        )
        .await
    }

    fn resolve_tls_server_id(
        &self,
        provisional_server_id: &str,
        local_addr: SocketAddr,
        tls_stream: &TlsStream<TcpStream>,
    ) -> String {
        let entrypoints = self.entrypoints.read();
        if let Some(port_server_id) = entrypoints.server_id_by_port.get(&local_addr.port()) {
            return port_server_id.clone();
        }

        let (_, connection) = tls_stream.get_ref();
        if let Some(server_name) = connection.server_name() {
            let name = normalize_sni_name(server_name);
            if let Some(server_id) = entrypoints.server_id_by_sni.get(&name) {
                return server_id.clone();
            }
        }

        if provisional_server_id.is_empty() {
            default_server_id()
        } else {
            provisional_server_id.to_owned()
        }
    }

    async fn handle_native_mumble_tls_connection(
        self: &Arc<Box<Self>>,
        mut tls_stream: TlsStream<TcpStream>,
        real_ip: std::net::IpAddr,
        remote_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        server_id: String,
        tls_ja4: Option<String>,
        uses_proxy_protocol: bool,
    ) -> Result<(), HandleIncomingConnectionError> {
        let authenticate_timeout =
            authenticate_timeout_duration(self.read_config().authenticate_timeout_ms);
        // Send server version (these are startup-only, read once)
        let version = {
            let cfg = self.read_config();
            Version::for_server_with_release(
                cfg.send_version,
                cfg.send_build_info,
                cfg.send_os_info,
                cfg.server_protocol_version,
                crate::constants::release,
            )
        }; // cfg dropped here
        tls_stream.write_proto_message(&version.into()).await?;

        let client = self
            .clients
            .allocate_local_client_in_server(
                server_id,
                real_ip,
                remote_addr,
                None,
                local_addr,
                tls_stream,
                tls_ja4,
                uses_proxy_protocol,
            )
            .await;

        let client_session_id = client.get_session_id();
        let client_span = client.tracing_span();

        // Subscriptions start as None — they're activated after auth.
        let mut client_log_rx: Option<ClientLogReceiver> = None;
        let mut channel_log_rx: Option<ChannelLogReceiver> = None;
        let mut writer_task = spawn_native_client_writer_task(&client);
        let mut channel_tree_shadow = ChannelTreeShadow::default();
        let mut session_channel_shadow: SessionChannelShadow = HashMap::new();
        let mut user_visibility = UserVisibilityState::default();

        // Run the connection loop.  On any unrecoverable error, clean up
        // the client and return the error to the caller.
        let result: Result<(), HandleIncomingConnectionError> = async {
            let mut handler_tasks = JoinSet::new();
            let mut pre_auth_handler_in_flight = false;
            let mut deferred_pre_auth_messages = VecDeque::new();
            let mut authenticate_deadline = Box::pin(tokio::time::sleep(authenticate_timeout));

            loop {
                tokio::select! {
                    // ── Authenticate timeout ────────────────────────────────
                    _ = &mut authenticate_deadline, if !client.is_authenticated() => {
                        tracing::info!(
                            server_id = %client.server_id(),
                            session = u32::from(client.get_session_id()),
                            timeout_ms = authenticate_timeout.as_millis(),
                            "closing connection after authenticate timeout"
                        );
                        return Err(HandleIncomingConnectionError::AuthenticateTimeout(authenticate_timeout));
                    }

                    // ── Local disconnect request ─────────────────────────────
                    _ = client.disconnected() => {
                        tracing::debug!(
                            session = u32::from(client.get_session_id()),
                            "closing connection after local disconnect request"
                        );
                        return Ok(());
                    }

                    // ── Completed client message handler ─────────────────────
                    result = handler_tasks.join_next(), if !handler_tasks.is_empty() => {
                        let Some(result) = result else { continue };
                        pre_auth_handler_in_flight = false;
                        let result = result
                            .map_err(HandleIncomingConnectionError::MessageHandlerTaskFailed)?;
                        finish_handler_result(
                            self,
                            &client,
                            client.get_session_id(),
                            &mut client_log_rx,
                            &mut channel_log_rx,
                            &mut channel_tree_shadow,
                            &mut session_channel_shadow,
                            &mut user_visibility,
                            result,
                        )
                        .await?;
                        client.touch_activity();
                        continue_deferred_client_messages(
                            &mut handler_tasks,
                            self,
                            &client,
                            &mut client_log_rx,
                            &mut channel_log_rx,
                            &mut channel_tree_shadow,
                            &mut session_channel_shadow,
                            &mut user_visibility,
                            &mut deferred_pre_auth_messages,
                            &mut pre_auth_handler_in_flight,
                        )
                        .await?;
                    }

                    // ── Dedicated writer task completion ─────────────────────
                    result = async {
                        match writer_task.as_mut() {
                            Some(task) => task.await,
                            None => std::future::pending().await,
                        }
                    }, if writer_task.is_some() => {
                        writer_task = None;
                        match result {
                            Ok(Ok(())) => return Ok(()),
                            Ok(Err(err)) => return Err(HandleIncomingConnectionError::ClientWriteFailed(err)),
                            Err(err) => return Err(HandleIncomingConnectionError::ClientWriterTaskFailed(err)),
                        }
                    }

                    // ── Deferred pre-auth message ───────────────────────────
                    _ = std::future::ready(()), if !pre_auth_handler_in_flight && !deferred_pre_auth_messages.is_empty() => {
                        continue_deferred_client_messages(
                            &mut handler_tasks,
                            self,
                            &client,
                            &mut client_log_rx,
                            &mut channel_log_rx,
                            &mut channel_tree_shadow,
                            &mut session_channel_shadow,
                            &mut user_visibility,
                            &mut deferred_pre_auth_messages,
                            &mut pre_auth_handler_in_flight,
                        )
                        .await?;
                    }

                    // ── Incoming message from this client ────────────────────
                    result = client.read_proto_message() => {
                        match result {
                            Ok(message) => {
                                if pre_auth_handler_in_flight {
                                    if is_pre_auth_dropped_message(&message) {
                                        if let Message::UDPTunnel(data) = &message {
                                            tracing::trace!(
                                                session = u32::from(client.get_session_id()),
                                                len = data.len(),
                                                "dropping UDPTunnel before authentication completed"
                                            );
                                        }
                                    } else if is_pre_auth_passthrough_message(&message) {
                                        finish_pre_auth_passthrough_message(self, &client, message).await?;
                                    } else if deferred_pre_auth_messages.len() < PRE_AUTH_DEFERRED_MESSAGE_LIMIT {
                                        deferred_pre_auth_messages.push_back(message);
                                    } else {
                                        return Err(HandleIncomingConnectionError::MessageHandlerFailed(
                                            MessageHandlerError::protocol_violation(
                                                "too many queued messages before authentication completed",
                                            ),
                                        ));
                                    }
                                } else if !client.is_authenticated()
                                    && is_pre_auth_dropped_message(&message)
                                {
                                    if let Message::UDPTunnel(data) = &message {
                                        tracing::trace!(
                                            session = u32::from(client.get_session_id()),
                                            len = data.len(),
                                            "dropping UDPTunnel before authentication completed"
                                        );
                                    }
                                } else if is_realtime_client_message(&message) {
                                    finish_normal_client_message(
                                        self,
                                        &client,
                                        &mut client_log_rx,
                                        &mut channel_log_rx,
                                        &mut channel_tree_shadow,
                                        &mut session_channel_shadow,
                                        &mut user_visibility,
                                        message,
                                    )
                                    .await?;
                                } else {
                                    let spawned_before_auth = !client.is_authenticated();
                                    spawn_client_message_handler(&mut handler_tasks, self, &client, message);
                                    if spawned_before_auth {
                                        // Version and Authenticate often arrive back-to-back in
                                        // one TCP read window. Keep pre-auth handlers ordered so
                                        // Authenticate sees the Version data before it builds the
                                        // authenticator auxiliary payload.
                                        pre_auth_handler_in_flight = true;
                                    }
                                }
                            }
                            Err(crate::errors::ReadProtoMessageError::UnknownMessageType(err)) => {
                                tracing::warn!(
                                    session = u32::from(client.get_session_id()),
                                    message_type = err.message_type,
                                    "client sent unknown message type; ignoring",
                                );
                                // Gracefully ignore unknown message types
                            }
                            Err(err) => return Err(HandleIncomingConnectionError::ReadProtoMessageError(err)),
                        }
                    }

                    // ── Channel state change notification ────────────────────
                    // Must come BEFORE client_log_rx in select! to ensure
                    // channel updates are delivered before client state updates.
                    result = recv_optional(channel_log_rx.as_mut()), if channel_log_rx.is_some() => {
                        if process_channel_log_result(
                            self,
                            &client,
                            client_session_id,
                            &mut channel_tree_shadow,
                            &mut session_channel_shadow,
                            &mut user_visibility,
                            result,
                        )
                        .await? == ChannelLogReceiveOutcome::Closed
                        {
                            return Ok(());
                        }
                    }

                    // ── Client state change notification ─────────────────────
                    result = recv_optional(client_log_rx.as_mut()), if client_log_rx.is_some() => {
                        if drain_ready_channel_log_before_client_log(
                            self,
                            &client,
                            client_session_id,
                            &mut channel_tree_shadow,
                            &mut session_channel_shadow,
                            &mut user_visibility,
                            &mut channel_log_rx,
                        )
                        .await? == ChannelLogReceiveOutcome::Closed
                        {
                            return Ok(());
                        }

                        match result {
                            Some(Ok(broadcast)) => {
                                if let Some(rx) = client_log_rx.as_mut() {
                                    process_client_log_broadcasts(
                                        self,
                                        &client,
                                        client_session_id,
                                        &mut channel_tree_shadow,
                                        &mut session_channel_shadow,
                                        &mut user_visibility,
                                        broadcast,
                                        rx,
                                    )
                                    .await?;
                                }
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                                replay_client_log_subscription_gap(
                                    self,
                                    &client,
                                    client_session_id,
                                    &mut channel_tree_shadow,
                                    &mut session_channel_shadow,
                                    &mut user_visibility,
                                )
                                .await?;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                                return Ok(());
                            }
                            None => {} // not subscribed yet
                        }
                    }
                }
            }
        }
        .instrument(client_span.clone())
        .await;

        // Single cleanup point: remove the client on any error.
        if result.is_err() {
            async {
                let server_id = client.server_id();
                let old_channel_id = client.get_current_channel_id();
                self.clients
                    .remove_client_instance_in_server(
                        &server_id,
                        client.get_session_id(),
                        client.client_instance_id(),
                    )
                    .await;
                crate::client::handlers::temp_channel::reap_if_empty_temporary_on_server(
                    self,
                    &server_id,
                    old_channel_id,
                )
                .await;
            }
            .instrument(client_span.clone())
            .await;
        }
        if let Err(error) = &result {
            client.in_tracing_scope(|| {
                if error.is_clean_disconnect() {
                    tracing::trace!("connection closed without TLS close_notify: {}", error);
                } else {
                    tracing::warn!("error handling connection: {}", error);
                }
            });
        }
        result
    }

    /// Attempt to reload config from disk. On success, applies live entrypoint
    /// bindings, atomically swaps the shared config, and logs changed keys.
    /// Returns an error only if the config file is malformed or an added
    /// entrypoint cannot be bound; the old config stays in place.
    pub async fn reload_config(self: &Arc<Box<Self>>) -> Result<(), Box<dyn std::error::Error>> {
        match Config::reload() {
            Ok(Some(new_config)) => {
                validate_privacy_config(&new_config)?;
                let next_tls_acceptor = load_c2s_tls_acceptor(&new_config, &self.extensions)?;
                let prepared_authenticator = self
                    .auth_finalization_queue
                    .prepare_authenticator_reload(&new_config)?;
                let authenticator_reloaded = prepared_authenticator.is_some();

                self.apply_entrypoint_config(&new_config).await?;

                let (root_channel_config_update, invalidate_acl_cache) = {
                    let mut invalidate_acl_cache = false;
                    let mut root_channel_config_update = None;
                    let mut current = self.config.write().expect("Config RwLock poisoned");
                    // Log notable changes
                    if current.welcome_text != new_config.welcome_text {
                        tracing::info!("config reload: welcome_text changed");
                    }
                    if current.root_channel_name != new_config.root_channel_name {
                        tracing::info!(
                            "config reload: root_channel_name {:?} -> {:?}",
                            current.root_channel_name,
                            new_config.root_channel_name
                        );
                        root_channel_config_update = Some(ChannelRootConfig::from(&new_config));
                    }
                    if current.max_bandwidth != new_config.max_bandwidth {
                        tracing::info!(
                            "config reload: max_bandwidth {} -> {}",
                            current.max_bandwidth,
                            new_config.max_bandwidth
                        );
                    }
                    if current.max_users != new_config.max_users {
                        tracing::info!(
                            "config reload: max_users {} -> {}",
                            current.max_users,
                            new_config.max_users
                        );
                        self.s2s_manager.update_max_users(new_config.max_users);
                    }
                    if current.authenticator != new_config.authenticator {
                        tracing::info!(
                            "config reload: authenticator {:?} -> {:?}",
                            current.authenticator,
                            new_config.authenticator
                        );
                    }
                    if current.cert_path != new_config.cert_path
                        || current.key_path != new_config.key_path
                    {
                        tracing::info!(
                            "config reload: C2S TLS identity paths {:?}/{:?} -> {:?}/{:?}",
                            current.cert_path,
                            current.key_path,
                            new_config.cert_path,
                            new_config.key_path
                        );
                    }
                    if current.s2s.overlay.route_transit_messages
                        != new_config.s2s.overlay.route_transit_messages
                    {
                        tracing::info!(
                            "config reload: s2s.overlay.route_transit_messages {} -> {}",
                            current.s2s.overlay.route_transit_messages,
                            new_config.s2s.overlay.route_transit_messages
                        );
                        self.s2s_manager.update_route_transit_messages(
                            new_config.s2s.overlay.route_transit_messages,
                        );
                    }
                    if current.udp_voice_enabled != new_config.udp_voice_enabled {
                        tracing::info!(
                            "config reload: udp_voice_enabled {} -> {}",
                            current.udp_voice_enabled,
                            new_config.udp_voice_enabled
                        );
                    }
                    if current.udp_ping_enabled != new_config.udp_ping_enabled {
                        tracing::info!(
                            "config reload: udp_ping_enabled {} -> {}",
                            current.udp_ping_enabled,
                            new_config.udp_ping_enabled
                        );
                    }
                    if current.udp_ping_user_count_scope != new_config.udp_ping_user_count_scope {
                        tracing::info!(
                            "config reload: udp_ping_user_count_scope {:?} -> {:?}",
                            current.udp_ping_user_count_scope,
                            new_config.udp_ping_user_count_scope
                        );
                    }
                    if current.client_idle_timeout_secs != new_config.client_idle_timeout_secs {
                        tracing::info!(
                            "config reload: client_idle_timeout_secs {} -> {}",
                            current.client_idle_timeout_secs,
                            new_config.client_idle_timeout_secs
                        );
                    }
                    if current.auth_finalization_concurrency
                        != new_config.auth_finalization_concurrency
                    {
                        tracing::info!(
                            "config reload: auth_finalization_concurrency {} -> {} (takes effect after restart)",
                            current.auth_finalization_concurrency,
                            new_config.auth_finalization_concurrency
                        );
                    }
                    if current.required_groups != new_config.required_groups {
                        tracing::info!("config reload: required_groups changed");
                    }
                    if current.geoip != new_config.geoip {
                        tracing::info!("config reload: geoip changed");
                        *self.geoip_resolver.write() =
                            Arc::new(GeoIpResolver::new(new_config.geoip.clone()));
                        invalidate_acl_cache = true;
                    }
                    if current.send_permission_info != new_config.send_permission_info {
                        tracing::info!(
                            "config reload: send_permission_info {} -> {}",
                            current.send_permission_info,
                            new_config.send_permission_info
                        );
                    }
                    if current.hide_users_without_traverse != new_config.hide_users_without_traverse
                    {
                        tracing::info!(
                            "config reload: hide_users_without_traverse {} -> {}",
                            current.hide_users_without_traverse,
                            new_config.hide_users_without_traverse
                        );
                    }
                    if current.acl.debug_acl_enter() != new_config.acl.debug_acl_enter() {
                        tracing::info!(
                            "config reload: acl.debug_acl_enter {} -> {}",
                            current.acl.debug_acl_enter(),
                            new_config.acl.debug_acl_enter()
                        );
                    }
                    if current.acl.explicit_enter_deny_overrides_write()
                        != new_config.acl.explicit_enter_deny_overrides_write()
                    {
                        tracing::info!(
                            "config reload: acl.explicit_enter_deny_overrides_write {} -> {}",
                            current.acl.explicit_enter_deny_overrides_write(),
                            new_config.acl.explicit_enter_deny_overrides_write()
                        );
                        invalidate_acl_cache = true;
                    }
                    if current.acl.preserve_write_acl_on_edit()
                        != new_config.acl.preserve_write_acl_on_edit()
                    {
                        tracing::info!(
                            "config reload: acl.preserve_write_acl_on_edit {} -> {}",
                            current.acl.preserve_write_acl_on_edit(),
                            new_config.acl.preserve_write_acl_on_edit()
                        );
                    }
                    if current.acl.grant_temp_channel_creator_acl()
                        != new_config.acl.grant_temp_channel_creator_acl()
                    {
                        tracing::info!(
                            "config reload: acl.grant_temp_channel_creator_acl {} -> {}",
                            current.acl.grant_temp_channel_creator_acl(),
                            new_config.acl.grant_temp_channel_creator_acl()
                        );
                    }
                    if current.acl.reevaluate_speak_on_acl_change()
                        != new_config.acl.reevaluate_speak_on_acl_change()
                    {
                        tracing::info!(
                            "config reload: acl.reevaluate_speak_on_acl_change {} -> {}",
                            current.acl.reevaluate_speak_on_acl_change(),
                            new_config.acl.reevaluate_speak_on_acl_change()
                        );
                    }
                    if current.privacy.certificate_hash_protection()
                        != new_config.privacy.certificate_hash_protection()
                    {
                        tracing::info!(
                            "config reload: privacy.protect_certificate_hashes {} -> {}",
                            current.privacy.certificate_hash_protection(),
                            new_config.privacy.certificate_hash_protection()
                        );
                    }
                    if current.privacy.certificate_hash_secret().is_some()
                        != new_config.privacy.certificate_hash_secret().is_some()
                    {
                        tracing::info!(
                            "config reload: privacy.certificate_hash_secret presence changed"
                        );
                    }
                    if current.server_entrypoints != new_config.server_entrypoints {
                        tracing::info!("config reload: server_entrypoints changed");
                    }
                    self.replace_c2s_tls_acceptor(next_tls_acceptor);
                    tracing::info!("config reload: C2S TLS identity refreshed");
                    *current = new_config;
                    (root_channel_config_update, invalidate_acl_cache)
                };
                if let Some(root_channel_config) = root_channel_config_update {
                    self.channels
                        .update_root_channel_config(root_channel_config)
                        .await;
                }
                if invalidate_acl_cache {
                    self.channels.invalidate_all_acl_cache().await;
                }
                self.auth_finalization_queue
                    .apply_prepared_authenticator_reload(prepared_authenticator);
                if authenticator_reloaded {
                    tracing::info!("config reload: authenticator backend reloaded");
                }
                tracing::info!("config reload: successfully applied new configuration");
                Ok(())
            }
            Ok(None) => {
                tracing::warn!("config reload: config.toml not found, keeping current config");
                Ok(())
            }
            Err(e) => {
                tracing::error!("config reload: failed to parse config.toml: {e}");
                Err(Box::new(e))
            }
        }
    }

    pub fn get_authenticator(&self) -> &dyn Authenticator {
        self.auth_finalization_queue.authenticator()
    }

    pub fn get_bans(&self) -> &Arc<crate::ban_repository::BanRepository> {
        &self.bans
    }

    pub fn get_clients(&self) -> &Arc<ClientRepository> {
        &self.clients
    }

    pub fn get_channels(&self) -> &Arc<ChannelRepository> {
        &self.channels
    }

    pub fn get_channel_blobs(&self) -> &Arc<ChannelBlobStore> {
        &self.channel_blobs
    }

    pub fn get_session_blobs(&self) -> &Arc<SessionBlobStore> {
        &self.session_blobs
    }

    pub fn get_user_channel_cache(&self) -> &Arc<UserChannelCache> {
        &self.user_channel_cache
    }

    pub fn get_udp_socket(&self) -> Option<Arc<tokio::net::UdpSocket>> {
        self.default_udp_socket()
    }

    pub fn s2s_manager(&self) -> &Arc<S2SManager> {
        &self.s2s_manager
    }

    pub fn get_codec_info(&self) -> parking_lot::MutexGuard<'_, CodecInfo> {
        self.codec_info.lock()
    }

    pub fn get_min_client_version(&self) -> u64 {
        self.read_config().min_client_version
    }

    pub fn get_max_users(&self) -> u64 {
        self.read_config().max_users
    }

    pub fn get_cert_required(&self) -> bool {
        self.read_config().cert_required
    }

    pub fn get_required_groups(&self) -> Vec<String> {
        self.read_config().required_groups.clone()
    }

    pub async fn acquire_auth_finalization_permit(
        self: &Arc<Box<Self>>,
        client: &Arc<Box<Client>>,
    ) -> Result<AuthFinalizationPermit, MessageHandlerError> {
        self.auth_finalization_queue.acquire(client).await
    }

    pub async fn create_client_crypt_state(
        &self,
        client: &Client,
        mode: &str,
    ) -> Result<(), crate::client::crypt::CryptError> {
        let permit = self
            .crypt_setup_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("crypt setup semaphore should not be closed");
        let result = client.create_crypt_state(mode);
        drop(permit);
        result
    }

    #[cfg(test)]
    pub(crate) fn install_auth_finalization_test_gate(
        &self,
        target_acquire: usize,
    ) -> AuthFinalizationTestGateHandle {
        self.auth_finalization_queue
            .install_test_gate(target_acquire)
    }

    pub fn get_send_permission_info(&self) -> bool {
        self.read_config().send_permission_info
    }

    pub fn get_hide_users_without_traverse(&self) -> bool {
        self.read_config().hide_users_without_traverse
    }

    pub fn get_debug_acl_enter(&self) -> bool {
        self.read_config().acl.debug_acl_enter()
    }

    pub fn get_explicit_enter_deny_overrides_write(&self) -> bool {
        self.read_config().acl.explicit_enter_deny_overrides_write()
    }

    pub fn get_preserve_write_acl_on_edit(&self) -> bool {
        self.read_config().acl.preserve_write_acl_on_edit()
    }

    pub fn get_grant_temp_channel_creator_acl(&self) -> bool {
        self.read_config().acl.grant_temp_channel_creator_acl()
    }

    pub fn get_reevaluate_speak_on_acl_change(&self) -> bool {
        self.read_config().acl.reevaluate_speak_on_acl_change()
    }

    pub(crate) async fn reevaluate_speak_after_acl_change(
        self: &Arc<Box<Self>>,
        server_id: &str,
        op: &ChannelOp,
        channel_version: u64,
    ) {
        if !self.get_reevaluate_speak_on_acl_change() {
            return;
        }
        let ChannelOp::SetAcls { .. } = op else {
            return;
        };
        let Some(affected_channel_ids) = self
            .get_channels()
            .acl_affected_channel_ids_for_op(server_id, op)
            .await
        else {
            return;
        };
        if affected_channel_ids.is_empty() {
            return;
        }

        let affected_clients = self
            .get_clients()
            .get_local_clients_in_channels_in_server(
                server_id,
                &sorted_channel_ids(&affected_channel_ids),
            )
            .await;

        for client in affected_clients {
            let permissions = crate::client::acl::compute_permissions_for_client(
                self,
                &client,
                client.get_current_channel_id(),
            )
            .await;
            let suppress = !permissions.contains(crate::acl::ACLPermissions::Speak);
            {
                let mut state =
                    client.write_global_state_as(self.get_clients(), None, Some(channel_version));
                state.set_suppress(suppress);
            }
        }
    }

    pub fn get_certificate_hash_privacy(&self) -> Option<(CertificateHashProtection, String)> {
        let config = self.read_config();
        let protection = config.privacy.certificate_hash_protection();
        if !protection.is_enabled() {
            return None;
        }
        let secret = config
            .privacy
            .certificate_hash_secret()
            .map(str::trim)
            .filter(|secret| !secret.is_empty())
            .map(ToOwned::to_owned)?;
        Some((protection, secret))
    }

    pub fn get_max_bandwidth(&self) -> u32 {
        self.read_config().max_bandwidth
    }

    pub fn get_server_protocol_version(&self) -> crate::protocol_version::ProtocolVersion {
        self.read_config().server_protocol_version
    }

    pub fn get_welcome_text(&self) -> Option<String> {
        self.read_config().welcome_text.clone()
    }

    pub fn get_allow_html(&self) -> bool {
        self.read_config().allow_html
    }

    pub fn get_max_text_message_length(&self) -> u32 {
        self.read_config().max_text_message_length
    }

    pub fn get_max_image_message_length(&self) -> u32 {
        self.read_config().max_image_message_length
    }

    pub fn get_default_channel(&self) -> u32 {
        self.read_config().default_channel
    }
    /// Access the context action registry.
    pub fn context_actions(&self) -> &Arc<crate::context_action::ContextActionRegistry> {
        &self.context_actions
    }

    // ── UDP ping ─────────────────────────────────────────────────────────

    async fn build_ping_response(
        server: &Arc<Box<Self>>,
        ping: &crate::voice::ping::PingRequest,
        status_server_id: &str,
    ) -> Result<Bytes, EncodeError> {
        // Snapshot config values before any .await (RwLockReadGuard is !Send)
        let (local_max_users, max_bandwidth, user_count_scope, server_version) = {
            let cfg = server.read_config();
            (
                cfg.max_users,
                cfg.max_bandwidth,
                cfg.udp_ping_user_count_scope,
                cfg.server_protocol_version,
            )
        };

        let (user_count, max_user_count) = match user_count_scope {
            UdpPingUserCountScope::Cluster => {
                let users = server.clients.len_in_server(status_server_id).await;
                let max_users = server
                    .s2s_manager
                    .cluster_max_users()
                    .filter(|max_users| *max_users > 0)
                    .unwrap_or(local_max_users);
                (users as u64, max_users)
            }
            UdpPingUserCountScope::Local => {
                let users = server.clients.local_len_in_server(status_server_id).await;
                (users as u64, local_max_users)
            }
        };

        let response = crate::voice::ping::PingResponse {
            timestamp: ping.timestamp,
            server_version,
            user_count: user_count.clamp(0, u32::MAX.into()) as u32,
            max_user_count: Some(max_user_count.clamp(0, u32::MAX.into()) as u32),
            max_bandwidth_per_user: max_bandwidth,
        };
        response.encode(ping.format)
    }

    // ── Codec negotiation ────────────────────────────────────────────────

    /// Re-evaluate codec selection across all authenticated clients and
    /// broadcast `CodecVersion` if the selection changed.
    pub async fn recheck_codec_versions(self: &Arc<Box<Self>>) {
        let all_clients = self.clients.get_all_clients().await;

        let mut alpha_count = 0usize;
        let mut beta_count = 0usize;
        let mut prefer_alpha_count = 0usize;
        let mut opus_count = 0usize;
        let total = all_clients.len();

        for client in &all_clients {
            if !client.is_authenticated() {
                continue;
            }
            let local = client.read_local_state();
            if let Some(ref state) = *local {
                if state.supports_opus() {
                    opus_count += 1;
                }
            }
        }

        let changed = {
            let mut codec = self.codec_info.lock();
            codec.recheck(
                alpha_count,
                beta_count,
                prefer_alpha_count,
                opus_count,
                total,
            )
        };

        if changed {
            let msg = {
                let codec = self.codec_info.lock();
                let alpha = codec.alpha_codec();
                let beta = codec.beta_codec();
                let prefer_alpha = codec.prefer_alpha_codec();
                let opus = codec.opus();
                // codec lock released here — block scope ends
                crate::messages::encoder::CodecVersion {
                    alpha,
                    beta,
                    prefer_alpha,
                    opus: Some(opus),
                }
                .into()
            };
            self.clients.broadcast_all(&msg).await;
        }
    }
}

use crate::channel_handler::replay_channel_log_gap;
use crate::utils::{recv_mpsc_optional, recv_optional};

// ─── Log gap replay helpers ─────────────────────────────────────────────────

/// Replay missed client-state log entries for `node_id` between `last` and
/// `current` (exclusive).  If `current == u64::MAX`, replays everything
/// after `last`.
///
/// Returns `Err(())` if the gap is unrecoverable (log pruned).
async fn replay_client_log_gap(
    client: &Arc<Box<crate::client::Client>>,
    repo: &crate::client_repository::ClientRepository,
    session_id: crate::client::client_session_identifier::ClientSessionIdentifier,
    node_id: u16,
    last: u64,
    current: u64,
) -> Result<(), ()> {
    if current <= last + 1 {
        return Ok(());
    }

    tracing::warn!(
        "Client {:?} missed client log entries: node={} last={} current={}",
        session_id,
        node_id,
        last,
        current,
    );

    let missed = repo.get_log_since_for_node(node_id, last).await;
    if missed.is_empty() && last > 0 {
        tracing::error!(
            "Client {:?} client log gap unrecoverable (node={}, last={})",
            session_id,
            node_id,
            last,
        );
        return Err(());
    }

    for entry in &missed {
        if entry.version >= current {
            break;
        }
        if is_own_client_log_entry(&entry.op, session_id, client.client_instance_id()) {
            continue;
        }
        if let Some(msg) = entry.to_message(repo).await {
            if client.write_proto_message(&msg).await.is_err() {
                return Err(());
            }
        }
        let mut ver = HashMap::new();
        ver.insert(entry.node_id, entry.version);
        client.update_last_client_versions(&ver).await;
    }

    Ok(())
}
