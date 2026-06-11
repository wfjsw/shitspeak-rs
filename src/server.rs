use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock as StdRwLock};

use bytes::{Bytes, BytesMut};
use parking_lot::{Mutex, RwLock as ParkingRwLock};
use rand::RngExt;

use cidr::AnyIpCidr;
use prost::{EncodeError, Message as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use rustls::version::{TLS12, TLS13};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::Instrument;

use crate::api::{Authenticator, ReloadableAuthenticator};
use crate::blob_store::{ChannelBlobStore, SessionBlobStore};
use crate::channel_handler::{ChannelTreeShadow, SessionChannelShadow};
use crate::channel_repository::{
    ChannelOperation, ChannelRepoTuning, ChannelRepository, ChannelRootConfig,
};
use crate::client::{
    AsyncMessageHandlerExt, Client, client_session_identifier::ClientSessionIdentifier,
    state_log::ClientStateBroadcastPayload, visibility::UserVisibilityState,
};
use crate::client_certificate_verifier::ClientCertificateVerifier;
use crate::errors::{HandleIncomingConnectionError, MessageHandlerError, ReadProtoMessageError};
use crate::messages::encoder::Version;
use crate::messages::{Message, WriteMessageExt};
use crate::proxy_protocol::get_proxy_protocol_client_address;
use crate::user_channel_cache::UserChannelCache;
use crate::{
    client_repository::ClientRepository,
    codec_info::CodecInfo,
    config::{Config, ServerEntrypointConfig, UdpPingUserCountScope},
    constants::MTU,
    s2s::S2SManager,
    types::{DEFAULT_SERVER_ID, NodeIdentifier, default_server_id},
};

type ClientLogReceiver = tokio::sync::broadcast::Receiver<Arc<ClientStateBroadcastPayload>>;
type ChannelLogReceiver = tokio::sync::broadcast::Receiver<Arc<ChannelOperation>>;
type UdpPacket = (Bytes, std::net::SocketAddr, std::net::SocketAddr);
#[cfg(feature = "web")]
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
const ALPN_MUMBLE: &[u8] = b"mumble";
const DYNAMIC_ENTRYPOINT_BIND_ATTEMPTS: usize = 128;
const DYNAMIC_ENTRYPOINT_MIN_PORT: u16 = 49152;
const DYNAMIC_ENTRYPOINT_MAX_PORT: u16 = 65535;

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

fn load_c2s_tls_acceptor(config: &Config) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let certificate = CertificateDer::pem_file_iter(&config.cert_path)
        .map_err(|e| startup_file_error("cert_path", &config.cert_path, "read TLS certificate", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            startup_file_error("cert_path", &config.cert_path, "parse TLS certificate", e)
        })?;
    let private_key = PrivateKeyDer::from_pem_file(&config.key_path)
        .map_err(|e| startup_file_error("key_path", &config.key_path, "read TLS private key", e))?;

    let client_cert_verifier = Arc::new(ClientCertificateVerifier::new());

    let mut tls_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS12, &TLS13])
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(certificate, private_key)?;
    #[cfg(feature = "web")]
    {
        tls_config.alpn_protocols.push(ALPN_HTTP_1_1.to_vec());
    }
    tls_config.alpn_protocols.push(ALPN_MUMBLE.to_vec());

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
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
    use super::*;
    use crate::api::{
        AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
    };
    use crate::localization::Language;
    use rustls::pki_types::ServerName;
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
        Config {
            listen: "127.0.0.1:0".to_owned(),
            server_entrypoints: entrypoints,
            register_name: "test".to_owned(),
            register_password: None,
            register_url: None,
            register_hostname: None,
            register_location: None,
            cert_path: "cert.pem".to_owned(),
            key_path: "key.pem".to_owned(),
            send_version: false,
            send_build_info: false,
            send_os_info: false,
            server_protocol_version: crate::constants::APP_PROTO_VER,
            allowed_proxies: Vec::new(),
            min_client_version: 0,
            max_users: 100,
            authenticator_wasm_path: None,
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
            pending_delete_timeout_ms: 5_000,
            required_groups: Vec::new(),
            send_permission_info: false,
            hide_users_without_traverse: false,
            debug: crate::config::DebugConfig::default(),
            s2s: crate::config::S2sConfig::default(),
            web: crate::config::WebConfig::default(),
        }
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

    async fn connect_tls_leaf_der(server: &Arc<Box<Server>>) -> Vec<u8> {
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
        drop(tls);
        match accept_task.await.expect("accept task joins") {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(err) => panic!("accept TLS: {err}"),
        }
        leaf
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
}

pub struct Server {
    node_identifier: NodeIdentifier,

    // Shared config — can be hot-reloaded at runtime
    config: Arc<StdRwLock<Config>>,

    allowed_proxies: Vec<AnyIpCidr>,

    tls_acceptor: ParkingRwLock<TlsAcceptor>,
    entrypoints: Arc<ParkingRwLock<EntrypointBindings>>,
    entrypoint_runtime: Mutex<Option<EntrypointRuntime>>,
    entrypoint_reload_lock: tokio::sync::Mutex<()>,

    clients: Arc<ClientRepository>,
    channels: Arc<ChannelRepository>,
    channel_blobs: Arc<ChannelBlobStore>,
    session_blobs: Arc<SessionBlobStore>,
    user_channel_cache: Arc<UserChannelCache>,
    bans: Arc<crate::ban_repository::BanRepository>,

    codec_info: Mutex<CodecInfo>,

    authenticator: Arc<ReloadableAuthenticator>,

    /// Registry of server-defined context menu actions.
    context_actions: Arc<crate::context_action::ContextActionRegistry>,

    s2s_manager: Arc<S2SManager>,
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

fn is_realtime_client_message(message: &Message) -> bool {
    matches!(message, Message::Ping(_) | Message::UDPTunnel(_))
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

    let staged_channel_subscription = client.take_channel_state_subscription();
    let channel_snapshot_version = staged_channel_subscription
        .as_ref()
        .map(|(version, _)| *version)
        .unwrap_or_else(|| server.channels.current_version_in_server(&server_id));
    client
        .set_last_channel_version(channel_snapshot_version)
        .await;
    channel_tree_shadow.clear();
    channel_tree_shadow.extend(
        server
            .channels
            .get_all_in_server(&server_id)
            .await
            .into_iter()
            .map(|channel| channel.id),
    );

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

    // --- PATCH: Replay missed entries before initializing visibility ---
    let last_seen = client.get_last_client_versions().await;
    let (missed, new_versions) = server
        .clients
        .replay_since_in_server(&server_id, &last_seen)
        .await
        .map_err(|()| HandleIncomingConnectionError::ClientLogGapUnrecoverable)?;
    for msg in &missed {
        let messages = crate::client::visibility::project_message_with_shadow(
            server,
            client,
            user_visibility,
            session_channel_shadow,
            &server_id,
            msg,
        )
        .await;
        for msg in messages {
            client
                .write_proto_message(&msg)
                .await
                .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
        }
    }
    client.update_last_client_versions(&new_versions).await;

    // Now rebuild visibility from the up-to-date state
    crate::client::visibility::initialize(server, client, user_visibility, session_channel_shadow)
        .await;
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

impl Server {
    pub async fn new<A: Authenticator>(
        config: Config,
        authenticator: A,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Self::new_with_reloadable_authenticator(
            config,
            ReloadableAuthenticator::fixed(authenticator),
        )
        .await
    }

    pub async fn new_with_reloadable_authenticator(
        config: Config,
        authenticator: ReloadableAuthenticator,
    ) -> Result<Arc<Box<Self>>, Box<dyn std::error::Error>> {
        Version::cache_server_os_info();

        let allowed_proxies = config
            .allowed_proxies
            .iter()
            .map(|proxy| AnyIpCidr::from_str(proxy))
            .collect::<Result<Vec<_>, _>>()?;

        let tls_acceptor = load_c2s_tls_acceptor(&config)?;

        let entrypoints = bind_entrypoints(&config).await?;

        // ── Channel repository & blob stores ─────────────────────────────
        let node_id = config.local_node_id().map_err(std::io::Error::other)?;
        let client_log_max_entries = config.client_log_max_entries;
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
            entrypoints: Arc::new(ParkingRwLock::new(entrypoints)),
            entrypoint_runtime: Mutex::new(None),
            entrypoint_reload_lock: tokio::sync::Mutex::new(()),
            clients: Arc::new(ClientRepository::new(node_id, client_log_max_entries)),
            channels,
            channel_blobs,
            session_blobs,
            user_channel_cache,
            bans,
            codec_info: Mutex::new(CodecInfo::default()),
            authenticator: Arc::new(authenticator),
            config,
            context_actions: Arc::new(crate::context_action::ContextActionRegistry::new()),
            s2s_manager,
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

    pub fn authenticator_wasm_path(&self) -> Option<PathBuf> {
        self.read_config().authenticator_wasm_path.clone()
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
        let tls_acceptor = load_c2s_tls_acceptor(new_config)?;
        self.replace_c2s_tls_acceptor(tls_acceptor);
        Ok(())
    }

    fn authenticator_arc(&self) -> Arc<dyn Authenticator> {
        let authenticator: Arc<dyn Authenticator> = self.authenticator.clone();
        authenticator
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
        let mut web_tasks = JoinSet::<()>::new();
        #[cfg(feature = "web")]
        {
            let startup_config = self.read_config().clone();
            let web_config = startup_config.web.clone();
            if web_config.enabled && web_config.listen.is_some() {
                let handle = crate::web::signaling::SignalingServer::new(web_config.clone())
                    .with_authenticator(self.authenticator_arc())
                    .with_server(Arc::clone(self))
                    .spawn(internal_rx.clone())?;
                web_tasks.spawn(async move {
                    let _ = handle.await;
                });
            }
            #[cfg(feature = "moq")]
            if web_config.enabled && web_config.moq.enabled && web_config.moq.listen.is_some() {
                let handle = crate::web::moq::MoqServer::new(web_config)
                    .with_tls_fallback(
                        startup_config.cert_path.clone(),
                        startup_config.key_path.clone(),
                    )
                    .with_authenticator(self.authenticator_arc())
                    .with_server(Arc::clone(self))
                    .spawn(internal_rx.clone())?;
                web_tasks.spawn(async move {
                    let _ = handle.await;
                });
            }
        }
        let s2s_task = Arc::clone(&self.s2s_manager)
            .spawn_runtime_task(Arc::downgrade(self), internal_rx.clone());

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
            result = web_tasks.join_next(), if !web_tasks.is_empty() => { let _ = result; }
            _ = shutdown_rx.changed() => {
                tracing::info!("Shutdown signal received.");
            }
        }

        // Ensure every spawned runtime task observes shutdown before joining.
        let _ = internal_tx.send(());

        let _ = udp_process.await;
        let _ = idle_reaper.await;
        let _ = pending_delete_watchdog.await;
        while web_tasks.join_next().await.is_some() {}
        s2s_task.join().await;
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
                        if !c.is_authenticated() {
                            tracing::trace!(
                                "UDP client {:?} matched by address is not authenticated, skipping",
                                c.get_session_id()
                            );
                            server
                                .clients
                                .unbind_client_udp_endpoint(local_addr, src_addr);
                        } else {
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
                    }

                    if found.is_none() {
                        let candidates = server.clients.get_clients_by_ip(&src_addr.ip()).await;
                        let mut matched = None;
                        for c in &candidates {
                            if !c.is_authenticated() {
                                tracing::trace!(
                                    "UDP client {:?} is not authenticated, skipping for IP fallback",
                                    c.get_session_id()
                                );
                                continue;
                            }

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

                // A valid UDP voice packet indicates UDP path is working.
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
                self.clients.remove_client_in_server(&server_id, sid).await;
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
                        if !server
                            .s2s_manager()
                            .propose_channel_op(Some(&server_id), op)
                            .await
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
        tcp_stream: tokio::net::TcpStream,
        remote_addr: std::net::SocketAddr,
        provisional_server_id: String,
    ) -> Result<(), HandleIncomingConnectionError> {
        let client_addr = if self
            .allowed_proxies
            .iter()
            .any(|proxy| proxy.contains(&remote_addr.ip()))
        {
            match get_proxy_protocol_client_address(&tcp_stream).await? {
                Some(addr) => SocketAddr::new(addr.ip(), addr.port()),
                None => remote_addr,
            }
        } else {
            remote_addr
        };
        let real_ip = client_addr.ip();

        let local_addr = tcp_stream.local_addr()?;
        let tls_acceptor = self.tls_acceptor.read().clone();
        let tls_stream = tls_acceptor.accept(tcp_stream).await?;
        let server_id = self.resolve_tls_server_id(&provisional_server_id, local_addr, &tls_stream);
        match tls_stream.get_ref().1.alpn_protocol() {
            #[cfg(feature = "web")]
            Some(ALPN_HTTP_1_1) => {
                let web = self.read_config().web.clone();
                crate::web::signaling::SignalingServer::new(web)
                    .with_authenticator(self.authenticator_arc())
                    .with_server(Arc::clone(self))
                    .with_provisional_server_id(server_id)
                    .handle_stream_with_peer(tls_stream, real_ip, client_addr, local_addr)
                    .await?;
                return Ok(());
            }
            Some(ALPN_MUMBLE) | None => {}
            Some(other) => {
                tracing::warn!(
                    protocol = %String::from_utf8_lossy(other),
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
    ) -> Result<(), HandleIncomingConnectionError> {
        // Send server version (these are startup-only, read once)
        let version = {
            let cfg = self.read_config();
            Version::for_server(
                cfg.send_version,
                cfg.send_build_info,
                cfg.send_os_info,
                cfg.server_protocol_version,
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
            )
            .await;

        let client_session_id = client.get_session_id();
        let client_span = client.tracing_span();

        // Subscriptions start as None — they're activated after auth.
        let mut client_log_rx: Option<ClientLogReceiver> = None;
        let mut channel_log_rx: Option<ChannelLogReceiver> = None;
        let mut channel_tree_shadow = ChannelTreeShadow::default();
        let mut session_channel_shadow: SessionChannelShadow = HashMap::new();
        let mut user_visibility = UserVisibilityState::default();

        // Run the connection loop.  On any unrecoverable error, clean up
        // the client and return the error to the caller.
        let result: Result<(), HandleIncomingConnectionError> = async {
            let mut handler_tasks = JoinSet::new();

            loop {
                tokio::select! {
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
                    }

                    // ── Incoming message from this client ────────────────────
                    result = client.read_proto_message() => {
                        match result {
                            Ok(message) => {
                                if is_realtime_client_message(&message) {
                                    let result = client.handle_message(self, message).await;
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
                                } else {
                                    let handler_server = Arc::clone(self);
                                    let handler_client = Arc::clone(&client);
                                    handler_tasks.spawn(async move {
                                        handler_client.handle_message(&handler_server, message).await
                                    });
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
                        match result {
            Some(Ok(op)) => {
                if op.server_id != client.server_id() {
                    continue;
                }
                let last = client.get_last_channel_version().await;
                if op.version <= last && !op.is_root_name_config_update() {
                    continue;
                }
                if op.version > last {
                                replay_channel_log_gap(
                                    self, &client, &self.channels, &mut channel_tree_shadow, &mut session_channel_shadow, &mut user_visibility, client_session_id, last, op.version,
                                ).await.map_err(|()| HandleIncomingConnectionError::ChannelLogGapUnrecoverable)?;
                }
                                let last_after_replay = client.get_last_channel_version().await;
                                if op.version <= last_after_replay && !op.is_root_name_config_update() {
                                    continue;
                                }

                                // Use unified message conversion function
                                let messages = crate::channel_handler::convert_channel_operation_to_messages_with_shadow(
                                    self,
                                    &client,
                                    &op,
                                    &self.channels,
                                    Some(&mut session_channel_shadow),
                                ).await;
                                for msg in messages {
                                    let projected = crate::client::visibility::project_message_with_shadow(
                                        self,
                                        &client,
                                        &mut user_visibility,
                                        &mut session_channel_shadow,
                                        &client.server_id(),
                                        &msg,
                                    ).await;
                                    for msg in projected {
                                        crate::channel_handler::sync_channel_tree_shadow(&mut channel_tree_shadow, &msg);
                                        client.write_proto_message(&msg).await
                                            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                    }
                                }
                                let reconcile = crate::client::visibility::reconcile_all(
                                    self,
                                    &client,
                                    &mut user_visibility,
                                ).await;
                                for msg in reconcile {
                                    let projected = crate::client::visibility::sync_projected_message_with_shadow(
                                        self,
                                        &client,
                                        &mut user_visibility,
                                        &mut session_channel_shadow,
                                        &client.server_id(),
                                        msg,
                                    ).await;
                                    for msg in projected {
                                        crate::channel_handler::sync_channel_tree_shadow(&mut channel_tree_shadow, &msg);
                                        client.write_proto_message(&msg).await
                                            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                    }
                                }
                                if op.version > last_after_replay {
                                    client.set_last_channel_version(op.version).await;
                                }
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                                let last = client.get_last_channel_version().await;
                                replay_channel_log_gap(
                                    self, &client, &self.channels, &mut channel_tree_shadow, &mut session_channel_shadow, &mut user_visibility, client_session_id, last, u64::MAX,
                                ).await.map_err(|()| HandleIncomingConnectionError::ChannelLogGapUnrecoverable)?;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                                return Ok(());
                            }
                            None => {} // not subscribed yet
                        }
                    }

                    // ── Client state change notification ─────────────────────
                    result = recv_optional(client_log_rx.as_mut()), if client_log_rx.is_some() => {
                        match result {
                            Some(Ok(broadcast)) => {
                                tracing::trace!("Received client log broadcast: {:?}", broadcast);

                                let entry = &broadcast.entry;
                                if entry.op.server_id() != client.server_id() {
                                    continue;
                                }
                                let mut last_seen = client.get_last_client_versions().await;
                                let mut last_for_node = last_seen.get(&entry.node_id).copied().unwrap_or(0);
                                // Owner-scoped S2S logs restart from version 1 after a node
                                // reboot, so connected clients must forget the old incarnation.
                                if broadcast
                                    .versions
                                    .get(&entry.node_id)
                                    .is_some_and(|current| *current < last_for_node)
                                {
                                    client.remove_last_client_version(entry.node_id).await;
                                    last_seen.remove(&entry.node_id);
                                    last_for_node = 0;
                                }
                                if entry.version <= last_for_node {
                                    continue;
                                }
                                if entry.version > last_for_node + 1 {
                                    let server_id = client.server_id();
                                    let (missed, new_versions) = self.clients.replay_since_in_server(&server_id, &last_seen).await
                                        .map_err(|()| HandleIncomingConnectionError::ClientLogGapUnrecoverable)?;
                                    for msg in &missed {
                                        let projected = crate::client::visibility::project_message_with_shadow(
                                            self,
                                            &client,
                                            &mut user_visibility,
                                            &mut session_channel_shadow,
                                            &server_id,
                                            msg,
                                        ).await;
                                        for msg in projected {
                                            client.write_proto_message(&msg).await
                                                .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                        }
                                    }
                                    let reconcile = crate::client::visibility::reconcile_all(
                                        self,
                                        &client,
                                        &mut user_visibility,
                                    ).await;
                                    for msg in reconcile {
                                        let projected = crate::client::visibility::sync_projected_message_with_shadow(
                                            self,
                                            &client,
                                            &mut user_visibility,
                                            &mut session_channel_shadow,
                                            &server_id,
                                            msg,
                                        ).await;
                                        for msg in projected {
                                            client.write_proto_message(&msg).await
                                                .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                        }
                                    }
                                    client.update_last_client_versions(&new_versions).await;
                                }

                                // If this entry has a channel version dependency,
                                // catch up the client's channel view to that dep first.
                                if let Some(dep) = entry.channel_version_dep {
                                    let last_ch = client.get_last_channel_version().await;
                                    if last_ch < dep {
                                        replay_channel_log_gap(
                                            self, &client, &self.channels, &mut channel_tree_shadow, &mut session_channel_shadow, &mut user_visibility, client_session_id, last_ch, dep + 1,
                                        ).await.map_err(|()| HandleIncomingConnectionError::ChannelLogGapUnrecoverable)?;
                                    }
                                }

                                if let Some(msg) = entry.to_message(&self.clients).await {
                                    let projected = crate::client::visibility::project_message_with_shadow(
                                        self,
                                        &client,
                                        &mut user_visibility,
                                        &mut session_channel_shadow,
                                        &client.server_id(),
                                        &msg,
                                    ).await;
                                    for msg in projected {
                                        client.write_proto_message(&msg).await
                                            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                    }
                                }
                                let reconcile = crate::client::visibility::reconcile_all(
                                    self,
                                    &client,
                                    &mut user_visibility,
                                ).await;
                                for msg in reconcile {
                                    let projected = crate::client::visibility::sync_projected_message_with_shadow(
                                        self,
                                        &client,
                                        &mut user_visibility,
                                        &mut session_channel_shadow,
                                        &client.server_id(),
                                        msg,
                                    ).await;
                                    for msg in projected {
                                        client.write_proto_message(&msg).await
                                            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                    }
                                }
                                client.update_last_client_versions(&broadcast.versions).await;
                            }
                            Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                                let last_seen = client.get_last_client_versions().await;
                                let server_id = client.server_id();
                                let (missed, new_versions) = self.clients.replay_since_in_server(&server_id, &last_seen).await
                                    .map_err(|()| HandleIncomingConnectionError::ClientLogGapUnrecoverable)?;
                                for msg in &missed {
                                    let projected = crate::client::visibility::project_message_with_shadow(
                                        self,
                                        &client,
                                        &mut user_visibility,
                                        &mut session_channel_shadow,
                                        &server_id,
                                        msg,
                                    ).await;
                                    for msg in projected {
                                        client.write_proto_message(&msg).await
                                            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                    }
                                }
                                let reconcile = crate::client::visibility::reconcile_all(
                                    self,
                                    &client,
                                    &mut user_visibility,
                                ).await;
                                for msg in reconcile {
                                    let projected = crate::client::visibility::sync_projected_message_with_shadow(
                                        self,
                                        &client,
                                        &mut user_visibility,
                                        &mut session_channel_shadow,
                                        &server_id,
                                        msg,
                                    ).await;
                                    for msg in projected {
                                        client.write_proto_message(&msg).await
                                            .map_err(HandleIncomingConnectionError::ClientWriteFailed)?;
                                    }
                                }
                                client.update_last_client_versions(&new_versions).await;
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
                    .remove_client_in_server(&server_id, client.get_session_id())
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
                let next_tls_acceptor = load_c2s_tls_acceptor(&new_config)?;
                let prepared_authenticator = self.authenticator.prepare_wasm_reload(
                    new_config.authenticator_wasm_path.as_deref(),
                    new_config.blob_storage_dir.as_deref(),
                )?;
                let authenticator_reloaded = prepared_authenticator.is_some();

                self.apply_entrypoint_config(&new_config).await?;

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
                    self.channels
                        .update_root_channel_config(ChannelRootConfig::from(&new_config))
                        .await;
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
                if current.authenticator_wasm_path != new_config.authenticator_wasm_path {
                    tracing::info!(
                        "config reload: authenticator_wasm_path {:?} -> {:?}",
                        current.authenticator_wasm_path,
                        new_config.authenticator_wasm_path
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
                if current.required_groups != new_config.required_groups {
                    tracing::info!("config reload: required_groups changed");
                }
                if current.send_permission_info != new_config.send_permission_info {
                    tracing::info!(
                        "config reload: send_permission_info {} -> {}",
                        current.send_permission_info,
                        new_config.send_permission_info
                    );
                }
                if current.hide_users_without_traverse != new_config.hide_users_without_traverse {
                    tracing::info!(
                        "config reload: hide_users_without_traverse {} -> {}",
                        current.hide_users_without_traverse,
                        new_config.hide_users_without_traverse
                    );
                }
                if current.debug.debug_acl_enter() != new_config.debug.debug_acl_enter() {
                    tracing::info!(
                        "config reload: debug.debug_acl_enter {} -> {}",
                        current.debug.debug_acl_enter(),
                        new_config.debug.debug_acl_enter()
                    );
                }
                if current.server_entrypoints != new_config.server_entrypoints {
                    tracing::info!("config reload: server_entrypoints changed");
                }
                self.replace_c2s_tls_acceptor(next_tls_acceptor);
                tracing::info!("config reload: C2S TLS identity refreshed");
                *current = new_config;
                drop(current);
                self.authenticator
                    .apply_prepared_reload(prepared_authenticator);
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
        self.authenticator.as_ref()
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

    pub fn get_send_permission_info(&self) -> bool {
        self.read_config().send_permission_info
    }

    pub fn get_hide_users_without_traverse(&self) -> bool {
        self.read_config().hide_users_without_traverse
    }

    pub fn get_debug_acl_enter(&self) -> bool {
        self.read_config().debug.debug_acl_enter()
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

use crate::channel_handler::{
    apply_permission_info_to_channel_state, convert_channel_operation_to_messages,
    replay_channel_log_gap,
};
use crate::utils::recv_optional;

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

    let missed = repo.get_log_since(last).await;
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
        if entry.op.session_id() == Some(session_id) {
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
