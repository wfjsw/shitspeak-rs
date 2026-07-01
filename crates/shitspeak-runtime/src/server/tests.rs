use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::*;
use crate::api::{
    AuthenticateAuxiliaryData, AuthenticateResult, AuthenticationRejection, Authenticator,
};
use crate::channel_handler::{ChannelTreeShadow, SessionChannelShadow};
use crate::client::{
    Client, client_session_identifier::ClientSessionIdentifier, visibility::UserVisibilityState,
};
use crate::config::{AuthenticatorConfig, Config, ServerEntrypointConfig, UdpPingUserCountScope};
use crate::localization::Language;
use crate::messages::encoder::TextMessage;
use crate::messages::{Message, WriteMessageExt};
use crate::types::DEFAULT_SERVER_ID;
use crate::voice::codec::PacketFormat;
use crate::voice::ping::PingRequest;
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
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
