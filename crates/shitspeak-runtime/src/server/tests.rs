use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::*;
use crate::api::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationExpiryAction,
    AuthenticationRejection, Authenticator,
};
use crate::channel_handler::{ChannelPermissionShadow, ChannelTreeShadow, SessionChannelShadow};
use crate::client::{
    Client, client_session_identifier::ClientSessionIdentifier, visibility::UserVisibilityState,
};
use crate::localization::Language;
use crate::messages::encoder::TextMessage;
use crate::messages::{Message, WriteMessageExt};
use crate::types::DEFAULT_SERVER_ID;
use crate::voice::codec::PacketFormat;
use crate::voice::ping::PingRequest;
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
use shitspeak_runtime_config::{
    AuthenticatorConfig, Config, ServerEntrypointConfig, UdpPingUserCountScope,
};
use tokio_rustls::TlsConnector;

struct TestAuthenticator;

#[derive(Debug, PartialEq, Eq)]
struct RecordedAuthentication {
    username: String,
    password: Option<String>,
    auth_session_id: Option<String>,
}

struct ControlledAuthenticator {
    calls: tokio::sync::mpsc::UnboundedSender<RecordedAuthentication>,
    responses: tokio::sync::Mutex<
        tokio::sync::mpsc::UnboundedReceiver<Result<AuthenticateResult, AuthenticationRejection>>,
    >,
}

fn controlled_authenticator() -> (
    ControlledAuthenticator,
    tokio::sync::mpsc::UnboundedReceiver<RecordedAuthentication>,
    tokio::sync::mpsc::UnboundedSender<Result<AuthenticateResult, AuthenticationRejection>>,
) {
    let (call_tx, call_rx) = tokio::sync::mpsc::unbounded_channel();
    let (response_tx, response_rx) = tokio::sync::mpsc::unbounded_channel();
    (
        ControlledAuthenticator {
            calls: call_tx,
            responses: tokio::sync::Mutex::new(response_rx),
        },
        call_rx,
        response_tx,
    )
}

#[async_trait::async_trait]
impl Authenticator for ControlledAuthenticator {
    async fn authenticate(
        &self,
        username: &str,
        password: Option<&str>,
        auxiliary_data: &AuthenticateAuxiliaryData,
    ) -> Result<AuthenticateResult, AuthenticationRejection> {
        self.calls
            .send(RecordedAuthentication {
                username: username.to_owned(),
                password: password.map(ToOwned::to_owned),
                auth_session_id: auxiliary_data.auth_session_id.clone(),
            })
            .expect("authentication test call receiver");
        self.responses
            .lock()
            .await
            .recv()
            .await
            .expect("authentication test response")
    }
}

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
            auth_session_id: None,
            authenticated_until: None,
            authentication_expiry_action: Default::default(),
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
        observability: shitspeak_runtime_config::ObservabilityConfig::default(),
        geoip: shitspeak_runtime_config::GeoIpConfig::default(),
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
        voice: shitspeak_runtime_config::VoiceTuning::default(),
        client_idle_timeout_secs: 30,
        authenticate_timeout_ms: 30_000,
        auth_finalization_concurrency: 4,
        pending_delete_timeout_ms: 5_000,
        required_groups: Vec::new(),
        send_permission_info: false,
        hide_users_without_traverse: false,
        hide_channels_without_traverse: false,
        show_node_id_for_superusers: true,
        acl: shitspeak_runtime_config::AclConfig::default(),
        s2s: shitspeak_runtime_config::S2sConfig::default(),
        web: shitspeak_runtime_config::WebConfig::default(),
        privacy: shitspeak_runtime_config::PrivacyConfig::default(),
    }
}

#[test]
fn channel_visibility_requires_user_visibility() {
    let mut config = test_config(Vec::new());
    config.hide_channels_without_traverse = true;
    assert!(validate_visibility_config(&config).is_err());

    config.hide_users_without_traverse = true;
    assert!(validate_visibility_config(&config).is_ok());
}

#[tokio::test]
async fn allow_move_without_traverse_reads_live_acl_config() {
    let server = Server::new(test_config(Vec::new()), TestAuthenticator)
        .await
        .expect("test server");
    assert!(!server.get_allow_move_without_traverse());

    {
        let mut config = server.config.write().expect("config lock");
        config.acl = config.acl.clone().with_allow_move_without_traverse(true);
    }
    assert!(server.get_allow_move_without_traverse());

    {
        let mut config = server.config.write().expect("config lock");
        config.acl = config.acl.clone().with_allow_move_without_traverse(false);
    }
    assert!(!server.get_allow_move_without_traverse());
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

    register_sni_entrypoints(&mut map, &entrypoint, &entrypoint.server_id).expect("SNI entrypoint");

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
fn udp_processing_channel_size_scales_from_max_users() {
    assert_eq!(effective_udp_processing_channel_size(2_048, 100), 12_800);
    assert_eq!(effective_udp_processing_channel_size(2_048, 400), 51_200);
}

#[test]
fn udp_processing_channel_size_keeps_configured_floor() {
    assert_eq!(effective_udp_processing_channel_size(70_000, 100), 70_000);
    assert_eq!(effective_udp_processing_channel_size(1, 0), 5_120);
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
    local_client.set_authenticated(true);
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
        .reap_expired_authentication_and_disconnect_idle_local_clients(
            chrono::Utc::now() + chrono::Duration::seconds(1),
            0,
        )
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

async fn authentication_expiry_test_client(server: &Arc<Box<Server>>) -> Arc<Box<Client>> {
    let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::channel(1);
    let client = server
        .clients
        .allocate_web_client_in_server(
            DEFAULT_SERVER_ID,
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1:51000".parse().unwrap(),
            "127.0.0.1:51001".parse().unwrap(),
            outbound_tx,
        )
        .await;
    client.set_authenticated(true);
    {
        let mut state = client.write_global_state(&server.clients);
        state.set_user_id(Some(7));
        state.set_display_name(Some("Original Name".to_owned()));
        state.set_groups(["original-group".to_owned()].into_iter().collect());
    }
    {
        let mut extended = client.user_info_extended().await;
        extended.set_credential(crate::client::user_info::Credential::new(
            "original-user".to_owned(),
            Some("original-password".to_owned()),
        ));
    }
    client
}

fn set_expiring_authentication(
    client: &Client,
    deadline: chrono::DateTime<chrono::Utc>,
    action: AuthenticationExpiryAction,
) {
    client.set_authentication_expiry(
        Some("previous-auth-session".to_owned()),
        Some(deadline),
        action,
    );
}

async fn authentication_expiry_reaper(
    server: &Arc<Box<Server>>,
    now: chrono::DateTime<chrono::Utc>,
) {
    server
        .reap_expired_authentication_and_disconnect_idle_local_clients(now, 86_400)
        .await;
}

#[tokio::test]
async fn authentication_expiry_before_deadline_is_ignored() {
    let server = Server::new(test_config(Vec::new()), TestAuthenticator)
        .await
        .expect("server");
    let client = authentication_expiry_test_client(&server).await;
    let deadline = chrono::Utc::now() + chrono::Duration::minutes(1);
    set_expiring_authentication(&client, deadline, AuthenticationExpiryAction::Kick);

    authentication_expiry_reaper(&server, deadline - chrono::Duration::milliseconds(1)).await;

    assert!(client.is_authenticated());
    assert_eq!(
        client
            .read_local_state()
            .as_ref()
            .expect("local state")
            .authenticated_until(),
        Some(deadline)
    );
    assert!(
        server
            .clients
            .get_client_in_server(DEFAULT_SERVER_ID, client.get_session_id())
            .await
            .is_some()
    );
}

#[tokio::test]
async fn authentication_expiry_kick_removes_client() {
    let server = Server::new(test_config(Vec::new()), TestAuthenticator)
        .await
        .expect("server");
    let client = authentication_expiry_test_client(&server).await;
    let session_id = client.get_session_id();
    let deadline = chrono::Utc::now();
    set_expiring_authentication(&client, deadline, AuthenticationExpiryAction::Kick);

    authentication_expiry_reaper(&server, deadline).await;

    assert!(
        server
            .clients
            .get_client_in_server(DEFAULT_SERVER_ID, session_id)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn authentication_expiry_deregister_only_clears_registration() {
    let server = Server::new(test_config(Vec::new()), TestAuthenticator)
        .await
        .expect("server");
    let client = authentication_expiry_test_client(&server).await;
    let session_id = client.get_session_id();
    let deadline = chrono::Utc::now();
    set_expiring_authentication(&client, deadline, AuthenticationExpiryAction::Deregister);

    authentication_expiry_reaper(&server, deadline).await;

    assert_eq!(client.get_user_id(), None);
    assert_eq!(client.display_name_opt().as_deref(), Some("Original Name"));
    assert_eq!(
        client.get_groups_clone(),
        ["original-group".to_owned()].into_iter().collect()
    );
    assert!(client.is_authenticated());
    assert!(
        server
            .clients
            .get_client_in_server(DEFAULT_SERVER_ID, session_id)
            .await
            .is_some()
    );
}

#[tokio::test]
async fn authentication_expiry_deregister_kicks_without_root_traverse() {
    let server = Server::new(test_config(Vec::new()), TestAuthenticator)
        .await
        .expect("server");
    server
        .channels
        .set_acls(
            0,
            true,
            vec![
                shitspeak_state::ACL {
                    user_id: None,
                    group: Some("all".to_owned()),
                    apply_here: true,
                    apply_subs: true,
                    allow: enumflags2::BitFlags::empty(),
                    deny: shitspeak_state::ACLPermissions::Traverse.into(),
                },
                shitspeak_state::ACL {
                    user_id: Some(7),
                    group: None,
                    apply_here: true,
                    apply_subs: true,
                    allow: shitspeak_state::ACLPermissions::Traverse.into(),
                    deny: enumflags2::BitFlags::empty(),
                },
            ],
        )
        .await
        .expect("root ACL");
    let client = authentication_expiry_test_client(&server).await;
    let session_id = client.get_session_id();
    assert!(server.client_has_root_traverse(&client).await);
    let deadline = chrono::Utc::now();
    set_expiring_authentication(&client, deadline, AuthenticationExpiryAction::Deregister);

    authentication_expiry_reaper(&server, deadline).await;

    assert!(
        server
            .clients
            .get_client_in_server(DEFAULT_SERVER_ID, session_id)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn authentication_expiry_reauth_preserves_state_while_pending_and_applies_success() {
    let (authenticator, mut calls, responses) = controlled_authenticator();
    let server = Server::new(test_config(Vec::new()), authenticator)
        .await
        .expect("server");
    let client = authentication_expiry_test_client(&server).await;
    let deadline = chrono::Utc::now();
    set_expiring_authentication(&client, deadline, AuthenticationExpiryAction::Reauth);

    authentication_expiry_reaper(&server, deadline).await;
    let call = tokio::time::timeout(Duration::from_secs(1), calls.recv())
        .await
        .expect("reauthentication started")
        .expect("reauthentication call");

    assert_eq!(
        call,
        RecordedAuthentication {
            username: "original-user".to_owned(),
            password: Some("original-password".to_owned()),
            auth_session_id: Some("previous-auth-session".to_owned()),
        }
    );
    assert!(client.is_authenticated());
    assert!(client.is_reauthentication_in_progress());
    assert_eq!(client.get_user_id(), Some(7));
    assert_eq!(client.display_name_opt().as_deref(), Some("Original Name"));
    assert_eq!(
        client.get_groups_clone(),
        ["original-group".to_owned()].into_iter().collect()
    );

    let next_deadline = deadline + chrono::Duration::hours(1);
    responses
        .send(Ok(AuthenticateResult {
            auth_session_id: Some("next-auth-session".to_owned()),
            authenticated_until: Some(next_deadline),
            authentication_expiry_action: AuthenticationExpiryAction::Kick,
            user_id: Some(42),
            display_name: Some("Updated Name".to_owned()),
            groups: vec!["updated-group".to_owned()],
            is_superuser: false,
            virtual_server_id: None,
            language: Language::default(),
            max_bandwidth: None,
            texture_url: None,
            comment_url: None,
        }))
        .expect("send successful reauthentication");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let complete = {
                let local = client.read_local_state();
                let local = local.as_ref().expect("local state");
                !local.is_reauthentication_in_progress()
                    && local.auth_session_id() == Some("next-auth-session")
            };
            if complete {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reauthentication completed");

    assert!(client.is_authenticated());
    assert_eq!(client.get_user_id(), Some(42));
    assert_eq!(client.display_name_opt().as_deref(), Some("Updated Name"));
    assert_eq!(
        client.get_groups_clone(),
        ["updated-group".to_owned()].into_iter().collect()
    );
    let local = client.read_local_state();
    let local = local.as_ref().expect("local state");
    assert_eq!(local.auth_session_id(), Some("next-auth-session"));
    assert_eq!(local.authenticated_until(), Some(next_deadline));
    assert_eq!(
        local.authentication_expiry_action(),
        AuthenticationExpiryAction::Kick
    );
}

#[tokio::test]
async fn authentication_expiry_reauth_rejection_kicks_client() {
    let (authenticator, mut calls, responses) = controlled_authenticator();
    let server = Server::new(test_config(Vec::new()), authenticator)
        .await
        .expect("server");
    let client = authentication_expiry_test_client(&server).await;
    let session_id = client.get_session_id();
    let deadline = chrono::Utc::now();
    set_expiring_authentication(&client, deadline, AuthenticationExpiryAction::Reauth);

    authentication_expiry_reaper(&server, deadline).await;
    tokio::time::timeout(Duration::from_secs(1), calls.recv())
        .await
        .expect("reauthentication started")
        .expect("reauthentication call");
    assert!(client.is_authenticated());
    responses
        .send(Err(AuthenticationRejection::WrongPassword))
        .expect("send rejected reauthentication");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if server
                .clients
                .get_client_in_server(DEFAULT_SERVER_ID, session_id)
                .await
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rejected client removed");
}

#[tokio::test]
async fn authentication_expiry_reauth_timeout_kicks_client() {
    let (authenticator, mut calls, _responses) = controlled_authenticator();
    let mut config = test_config(Vec::new());
    config.authenticate_timeout_ms = 20;
    let server = Server::new(config, authenticator).await.expect("server");
    let client = authentication_expiry_test_client(&server).await;
    let session_id = client.get_session_id();
    let deadline = chrono::Utc::now();
    set_expiring_authentication(&client, deadline, AuthenticationExpiryAction::Reauth);

    authentication_expiry_reaper(&server, deadline).await;
    tokio::time::timeout(Duration::from_secs(1), calls.recv())
        .await
        .expect("reauthentication started")
        .expect("reauthentication call");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if server
                .clients
                .get_client_in_server(DEFAULT_SERVER_ID, session_id)
                .await
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed-out client removed");
}

#[tokio::test]
async fn authentication_expiry_reauth_budget_defers_excess_clients() {
    let (authenticator, mut calls, responses) = controlled_authenticator();
    let mut config = test_config(Vec::new());
    config.auth_finalization_concurrency = 1;
    let server = Server::new(config, authenticator).await.expect("server");
    let first = authentication_expiry_test_client(&server).await;
    let second = authentication_expiry_test_client(&server).await;
    let deadline = chrono::Utc::now();
    set_expiring_authentication(&first, deadline, AuthenticationExpiryAction::Reauth);
    set_expiring_authentication(&second, deadline, AuthenticationExpiryAction::Reauth);

    authentication_expiry_reaper(&server, deadline).await;
    tokio::time::timeout(Duration::from_secs(1), calls.recv())
        .await
        .expect("first reauthentication started")
        .expect("first reauthentication call");

    let deferred = [&first, &second]
        .into_iter()
        .find(|client| !client.is_reauthentication_in_progress())
        .expect("one expired reauthentication remains deferred");
    let local = deferred.read_local_state();
    let local = local.as_ref().expect("local state");
    assert!(local.is_authenticated());
    assert_eq!(local.authenticated_until(), Some(deadline));

    responses
        .send(Err(AuthenticationRejection::WrongPassword))
        .expect("release first reauthentication");
}

#[tokio::test]
async fn detached_client_waiting_for_reauth_permit_does_not_call_authenticator() {
    let (authenticator, mut calls, _responses) = controlled_authenticator();
    let mut config = test_config(Vec::new());
    config.auth_finalization_concurrency = 1;
    let server = Server::new(config, authenticator).await.expect("server");
    let permit = server.auth_finalization_queue.acquire_silent().await;
    let client = authentication_expiry_test_client(&server).await;
    let deadline = chrono::Utc::now();
    set_expiring_authentication(&client, deadline, AuthenticationExpiryAction::Reauth);

    authentication_expiry_reaper(&server, deadline).await;
    server
        .clients
        .remove_client_instance_in_server(
            DEFAULT_SERVER_ID,
            client.get_session_id(),
            client.client_instance_id(),
        )
        .await;
    drop(permit);

    assert!(
        tokio::time::timeout(Duration::from_millis(100), calls.recv())
            .await
            .is_err(),
        "detached client unexpectedly reached authenticator"
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
async fn sharded_and_legacy_activation_match_for_missed_client_add() {
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
    let mut viewer_session_shadow = SessionChannelShadow::new();
    viewer_session_shadow.insert(viewer_session, viewer.get_current_channel_id());
    viewer.stage_post_auth_baseline(crate::client::PostAuthBaseline::new(
        viewer_session_shadow,
        channels.iter().map(|channel| channel.id).collect(),
    ));

    let legacy_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31003);
    let legacy_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64740);
    let (legacy_tx, mut legacy_rx) = tokio::sync::mpsc::channel(16);
    let legacy_viewer = server
        .clients
        .allocate_web_client_in_server(
            DEFAULT_SERVER_ID,
            legacy_peer.ip(),
            legacy_peer,
            legacy_local,
            legacy_tx,
        )
        .await;
    legacy_viewer.set_authenticated(true);
    let legacy_session = legacy_viewer.get_session_id();
    let (_clients, legacy_versions, legacy_client_state_rx) = server
        .clients
        .snapshot_with_versions_and_subscription_in_server(DEFAULT_SERVER_ID)
        .await;
    legacy_viewer.stage_client_state_subscription(legacy_client_state_rx);
    legacy_viewer
        .update_last_client_versions(&legacy_versions)
        .await;
    let (legacy_channels, legacy_channel_version, legacy_channel_state_rx) = server
        .channels
        .snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
    legacy_viewer.stage_channel_state_subscription(legacy_channel_version, legacy_channel_state_rx);
    let mut legacy_session_shadow = SessionChannelShadow::new();
    legacy_session_shadow.insert(legacy_session, legacy_viewer.get_current_channel_id());
    legacy_viewer.stage_post_auth_baseline(crate::client::PostAuthBaseline::new(
        legacy_session_shadow,
        legacy_channels.iter().map(|channel| channel.id).collect(),
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

    let mut legacy_client_log_rx = None;
    let mut legacy_channel_log_rx = None;
    let mut legacy_channel_tree_shadow = ChannelTreeShadow::default();
    let mut legacy_channel_permission_shadow = ChannelPermissionShadow::default();
    let mut legacy_session_channel_shadow = SessionChannelShadow::default();
    let mut legacy_user_visibility = UserVisibilityState::default();
    activate_client_subscriptions(
        &server,
        &legacy_viewer,
        legacy_session,
        &mut legacy_client_log_rx,
        &mut legacy_channel_log_rx,
        &mut legacy_channel_tree_shadow,
        &mut legacy_channel_permission_shadow,
        &mut legacy_session_channel_shadow,
        &mut legacy_user_visibility,
    )
    .await
    .expect("legacy activation succeeds");

    let mut projection_registration = None;
    activate_client_projection(&server, &viewer, &mut projection_registration)
        .await
        .expect("sharded activation succeeds");

    let sharded_target = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(message) = viewer_rx.recv().await {
            if let Message::UserState(user) = message
                && user.session == Some(u32::from(target_session))
            {
                return user;
            }
        }
        panic!("sharded activation queue closed before target UserState");
    })
    .await
    .expect("sharded activation should replay target UserState");
    let legacy_target = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(message) = legacy_rx.recv().await {
            if let Message::UserState(user) = message
                && user.session == Some(u32::from(target_session))
            {
                return user;
            }
        }
        panic!("legacy activation queue closed before target UserState");
    })
    .await
    .expect("legacy activation should replay target UserState");

    assert_eq!(
        format!("{sharded_target:?}"),
        format!("{legacy_target:?}"),
        "sharded replay must match the legacy per-connection projection"
    );
    assert!(projection_registration.is_some());
}

async fn stage_projection_parity_viewer(
    server: &Arc<Box<Server>>,
    peer_port: u16,
    local_port: u16,
) -> (Arc<Box<Client>>, tokio::sync::mpsc::Receiver<Message>) {
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), peer_port);
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let viewer = server
        .clients
        .allocate_web_client_in_server(DEFAULT_SERVER_ID, peer.ip(), peer, local, tx)
        .await;
    viewer.set_authenticated(true);

    let (published_clients, versions, client_state_rx) = server
        .clients
        .published_snapshot_with_versions_and_subscription_in_server(DEFAULT_SERVER_ID)
        .await;
    viewer.stage_client_state_subscription(client_state_rx);
    viewer.update_last_client_versions(&versions).await;

    let (channels, channel_version, channel_state_rx) = server
        .channels
        .snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
    viewer.stage_channel_state_subscription(channel_version, channel_state_rx);

    let mut session_shadow = SessionChannelShadow::new();
    session_shadow.extend(
        published_clients
            .into_iter()
            .filter(|client| client.is_authenticated())
            .map(|client| (client.get_session_id(), client.get_current_channel_id())),
    );
    session_shadow.insert(viewer.get_session_id(), viewer.get_current_channel_id());
    viewer.stage_post_auth_baseline(crate::client::PostAuthBaseline::new(
        session_shadow,
        channels.iter().map(|channel| channel.id).collect(),
    ));

    (viewer, rx)
}

async fn activate_legacy_projection_for_parity(
    server: &Arc<Box<Server>>,
    viewer: &Arc<Box<Client>>,
) {
    let mut client_log_rx = None;
    let mut channel_log_rx = None;
    let mut channel_tree_shadow = ChannelTreeShadow::default();
    let mut channel_permission_shadow = ChannelPermissionShadow::default();
    let mut session_channel_shadow = SessionChannelShadow::default();
    let mut user_visibility = UserVisibilityState::default();
    activate_client_subscriptions(
        server,
        viewer,
        viewer.get_session_id(),
        &mut client_log_rx,
        &mut channel_log_rx,
        &mut channel_tree_shadow,
        &mut channel_permission_shadow,
        &mut session_channel_shadow,
        &mut user_visibility,
    )
    .await
    .expect("legacy activation succeeds");
}

#[tokio::test]
async fn sharded_and_legacy_activation_match_for_missed_target_move() {
    install_default_provider();
    let server = Server::new(test_config(Vec::new()), TestAuthenticator)
        .await
        .expect("server");

    let target_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31101);
    let target_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64801);
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

    let (sharded_viewer, mut sharded_rx) =
        stage_projection_parity_viewer(&server, 31102, 64802).await;
    let (legacy_viewer, mut legacy_rx) =
        stage_projection_parity_viewer(&server, 31103, 64803).await;

    let channel_version = server.channels.current_version_in_server(DEFAULT_SERVER_ID);
    target.set_current_channel_id(42, &server.clients, channel_version);

    activate_legacy_projection_for_parity(&server, &legacy_viewer).await;
    let mut projection_registration = None;
    activate_client_projection(&server, &sharded_viewer, &mut projection_registration)
        .await
        .expect("sharded activation succeeds");

    let sharded_move = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(message) = sharded_rx.recv().await {
            if let Message::UserState(user) = message
                && user.session == Some(u32::from(target_session))
                && user.channel_id == Some(42)
            {
                return user;
            }
        }
        panic!("sharded activation queue closed before target move");
    })
    .await
    .expect("sharded activation should replay target move");
    let legacy_move = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(message) = legacy_rx.recv().await {
            if let Message::UserState(user) = message
                && user.session == Some(u32::from(target_session))
                && user.channel_id == Some(42)
            {
                return user;
            }
        }
        panic!("legacy activation queue closed before target move");
    })
    .await
    .expect("legacy activation should replay target move");

    assert_eq!(
        format!("{sharded_move:?}"),
        format!("{legacy_move:?}"),
        "sharded target-move replay must match the legacy projection"
    );
    assert!(projection_registration.is_some());
}

#[tokio::test]
async fn sharded_and_legacy_activation_match_for_missed_target_disconnect() {
    install_default_provider();
    let server = Server::new(test_config(Vec::new()), TestAuthenticator)
        .await
        .expect("server");

    let target_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31201);
    let target_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64901);
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

    let (sharded_viewer, mut sharded_rx) =
        stage_projection_parity_viewer(&server, 31202, 64902).await;
    let (legacy_viewer, mut legacy_rx) =
        stage_projection_parity_viewer(&server, 31203, 64903).await;

    server
        .clients
        .remove_client_in_server(DEFAULT_SERVER_ID, target_session)
        .await
        .expect("target is removed");

    activate_legacy_projection_for_parity(&server, &legacy_viewer).await;
    let mut projection_registration = None;
    activate_client_projection(&server, &sharded_viewer, &mut projection_registration)
        .await
        .expect("sharded activation succeeds");

    let sharded_remove = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(message) = sharded_rx.recv().await {
            if let Message::UserRemove(remove) = message
                && remove.session == u32::from(target_session)
            {
                return remove;
            }
        }
        panic!("sharded activation queue closed before target removal");
    })
    .await
    .expect("sharded activation should replay target removal");
    let legacy_remove = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(message) = legacy_rx.recv().await {
            if let Message::UserRemove(remove) = message
                && remove.session == u32::from(target_session)
            {
                return remove;
            }
        }
        panic!("legacy activation queue closed before target removal");
    })
    .await
    .expect("legacy activation should replay target removal");

    assert_eq!(
        format!("{sharded_remove:?}"),
        format!("{legacy_remove:?}"),
        "sharded target-removal replay must match the legacy projection"
    );
    assert!(projection_registration.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sharded_visibility_reload_is_ordered_and_does_not_wait_for_full_writer() {
    use super::client_projection::{ClientProjectionEvent, ClientProjectionState};
    use super::sharded_subscriber::{MIN_PROJECTION_SHARDS, ShardedSubscriberPool};

    install_default_provider();
    let server = Server::new(test_config(Vec::new()), TestAuthenticator)
        .await
        .expect("server");

    let slow_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31101);
    let fast_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31102);
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 64738);
    let (slow_tx, mut slow_rx) = tokio::sync::mpsc::channel(1);
    let (fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(16);
    let slow = server
        .clients
        .allocate_web_client_in_server(DEFAULT_SERVER_ID, slow_peer.ip(), slow_peer, local, slow_tx)
        .await;
    let fast = server
        .clients
        .allocate_web_client_in_server(DEFAULT_SERVER_ID, fast_peer.ip(), fast_peer, local, fast_tx)
        .await;
    for client in [&slow, &fast] {
        client.set_authenticated(true);
        server
            .clients
            .publish_client_in_server(DEFAULT_SERVER_ID, client.get_session_id())
            .await;
    }

    let snapshot = server
        .clients
        .published_snapshot_with_versions_in_server(DEFAULT_SERVER_ID)
        .await;
    let (published, client_versions) = snapshot.into_parts();
    let (channels, channel_version, channel_rx) = server
        .channels
        .snapshot_with_version_and_subscription_in_server(DEFAULT_SERVER_ID);
    drop(channel_rx);
    let mut session_shadow = SessionChannelShadow::new();
    session_shadow.extend(
        published
            .iter()
            .map(|client| (client.get_session_id(), client.get_current_channel_id())),
    );
    let channel_shadow = channels
        .iter()
        .map(|channel| channel.id)
        .collect::<ChannelTreeShadow>();
    let make_state = |client: &Arc<Box<Client>>| {
        ClientProjectionState::new(
            Arc::downgrade(&server),
            Arc::clone(client),
            channel_shadow.clone(),
            session_shadow.clone(),
            UserVisibilityState::default(),
            client_versions.clone(),
            channel_version,
        )
    };

    let (event_tx, _) = tokio::sync::broadcast::channel(8);
    let pool = ShardedSubscriberPool::new(&event_tx, MIN_PROJECTION_SHARDS).expect("pool");
    let slow_registration = pool
        .register("visibility-reload", make_state(&slow))
        .await
        .expect("slow registration");
    let fast_registration = pool
        .register("visibility-reload", make_state(&fast))
        .await
        .expect("fast registration");
    assert_eq!(
        slow_registration.shard_index(),
        fast_registration.shard_index(),
        "the full and writable queues must be exercised by the same shard"
    );

    let prefill = Message::TextMessage(
        TextMessage {
            actor: None,
            session: Vec::new(),
            channel_id: Vec::new(),
            tree_id: Vec::new(),
            message: "prefill".to_owned(),
        }
        .into(),
    );
    slow.write_proto_message(&prefill)
        .await
        .expect("prefill slow writer");
    {
        let mut config = server.config.write().expect("config lock");
        config.hide_users_without_traverse = true;
    }
    event_tx
        .send(ClientProjectionEvent::VisibilityReload)
        .expect("visibility reload has shard receivers");

    let projected_sessions = tokio::time::timeout(Duration::from_secs(1), async {
        let mut sessions = Vec::new();
        while sessions.len() < 2 {
            let message = fast_rx.recv().await.expect("fast writer remains open");
            if let Message::UserState(state) = message {
                if let Some(session) = state.session {
                    sessions.push(session);
                }
            }
        }
        sessions
    })
    .await
    .expect("full peer queue must not stall visibility reload delivery");
    assert!(
        projected_sessions.windows(2).all(|pair| pair[0] < pair[1]),
        "reload projection must retain deterministic session order: {projected_sessions:?}"
    );
    tokio::time::timeout(Duration::from_secs(1), slow.disconnected())
        .await
        .expect("a full writer is removed without awaiting queue capacity");
    assert!(matches!(
        slow_rx.recv().await,
        Some(Message::TextMessage(message)) if message.message == "prefill"
    ));
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
    let mut second_task = tokio::spawn(async move { second_queue.acquire(&second_client).await });
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
