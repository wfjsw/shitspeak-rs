//! Auth-flow scenarios: success, wrong password, unknown user, server full,
//! and `cert_required` rejection.

use crate::acl::{ACL, ACLPermissions};
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::localization::Language;
use crate::messages::encoder::{ContextActionModify, RejectType};
use crate::messages::{Message, ReadMessageExt, WriteMessageExt};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

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

/// Checks that two registered users can authenticate concurrently.
/// Expected: each client gets a distinct session, its registered user id, and
/// the configured welcome text. This follows Mumble's auth/ServerSync path in
/// `D:\mumble\src\murmur\Messages.cpp::msgAuthenticate` and shitspeak's
/// equivalent authenticate flow in `D:\shitspeak\server.go::handleAuthenticate`.
#[tokio::test]
async fn auth_two_clients_succeeds() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob auth");

    assert_ne!(alice.session_id, 0, "alice should have a session id");
    assert_ne!(bob.session_id, 0, "bob should have a session id");
    assert_ne!(alice.session_id, bob.session_id, "sessions must differ");

    assert_eq!(alice.user_id, Some(1));
    assert_eq!(bob.user_id, Some(2));
    assert_eq!(server.authenticator.authenticate_call_count("alice"), 1);
    assert_eq!(server.authenticator.authenticate_call_count("bob"), 1);

    // Both clients receive the welcome text we configured.
    assert_eq!(alice.welcome_text.as_deref(), Some("test-welcome"));
    assert_eq!(bob.welcome_text.as_deref(), Some("test-welcome"));
}

#[tokio::test]
async fn authenticator_receives_tls_ja4_and_proxy_protocol_flag() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let _alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");

    let auxiliary = server.authenticator.authenticated_auxiliary_data();
    let auxiliary = auxiliary
        .last()
        .expect("authenticator should record auth data");
    let tls_ja4 = auxiliary
        .tls_ja4()
        .expect("native TLS connection should have a JA4 fingerprint");
    assert!(
        tls_ja4.starts_with("t13x"),
        "SNI-redacted TLS 1.3 JA4: {tls_ja4}"
    );
    assert!(
        !auxiliary.uses_proxy_protocol(),
        "direct test connection should not use PROXY protocol"
    );
    assert_eq!(auxiliary.ip_address(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        auxiliary.version(),
        Some(crate::protocol_version::ProtocolVersion::new(1, 5, 0))
    );
    assert_eq!(auxiliary.client_name(), Some("test-client"));
    assert_eq!(auxiliary.os_name(), Some("test"));
    assert_eq!(auxiliary.os_version(), Some("test"));
}

#[tokio::test]
async fn native_client_must_authenticate_before_timeout() {
    let server = spawn_test_server(TestServerOpts {
        authenticate_timeout_ms: 50,
        ..TestServerOpts::default()
    })
    .await;

    let key_pair = KeyPair::generate().expect("client keypair");
    let mut cert_params =
        CertificateParams::new(vec!["test-client".into()]).expect("client cert params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-client");
    cert_params.distinguished_name = dn;
    let cert = cert_params
        .self_signed(&key_pair)
        .expect("self-signed client cert");
    let cert_der = CertificateDer::pem_slice_iter(cert.pem().as_bytes())
        .next()
        .expect("client cert pem contains cert")
        .expect("parse client cert");
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_slice(key_pair.serialize_pem().as_bytes())
            .expect("parse client key");
    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_client_auth_cert(vec![cert_der], key_der)
        .expect("client TLS config");
    let connector = TlsConnector::from(Arc::new(tls_config));

    let tcp = TcpStream::connect(server.addr).await.expect("TCP connect");
    let server_name = ServerName::try_from("localhost").expect("static server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake");

    let version = tls.read_proto_message().await.expect("server Version");
    assert!(matches!(version, Message::Version(_)));
    tls.write_proto_message(
        &crate::messages::encoder::Version {
            version: Some(crate::protocol_version::ProtocolVersion::new(1, 5, 0)),
            release: Some("test-client".into()),
            os: Some("test".into()),
            os_version: Some("test".into()),
        }
        .into(),
    )
    .await
    .expect("write client Version");

    let closed = timeout(Duration::from_secs(2), tls.read_proto_message())
        .await
        .expect("connection should close after authenticate timeout");
    assert!(
        closed.is_err(),
        "server should close unauthenticated native client"
    );
}

#[tokio::test]
async fn certificate_hash_privacy_remaps_other_users_only() {
    let privacy = crate::config::PrivacyConfig::new(
        true,
        Some("test-shared-certificate-hash-secret".to_owned()),
    );
    let server = spawn_test_server(TestServerOpts {
        privacy,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob auth");

    let bob_self_hash = hex::encode(bob.cert_sha1());
    let bob_self_state = bob
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(bob.session_id))
        .expect("bob should receive his own UserState");
    assert_eq!(bob_self_state.hash.as_deref(), Some(bob_self_hash.as_str()));

    let alice_bob_state = alice
        .recv_until(
            |message| matches!(message, Message::UserState(state) if state.session == Some(bob.session_id)),
            std::time::Duration::from_secs(2),
        )
        .await
        .or_else(|| {
            alice
                .initial_user_states
                .iter()
                .find(|state| state.session == Some(bob.session_id))
                .cloned()
                .map(Message::UserState)
        })
        .expect("alice should see bob");
    let Message::UserState(alice_bob_state) = alice_bob_state else {
        panic!("expected Bob UserState");
    };
    let expected = crate::privacy::remapped_certificate_hash_hex(
        "test-shared-certificate-hash-secret",
        &bob_self_hash,
    )
    .expect("valid test hash");
    assert_eq!(alice_bob_state.hash.as_deref(), Some(expected.as_str()));
    assert_ne!(
        alice_bob_state.hash.as_deref(),
        Some(bob_self_hash.as_str())
    );
}

#[tokio::test]
async fn certificate_hash_privacy_reversible_remaps_other_users_only() {
    let privacy = crate::config::PrivacyConfig::with_certificate_hash_protection(
        crate::config::CertificateHashProtection::Reversible,
        Some("test-shared-certificate-hash-secret".to_owned()),
    );
    let server = spawn_test_server(TestServerOpts {
        privacy,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob auth");

    let bob_self_hash = hex::encode(bob.cert_sha1());
    let bob_self_state = bob
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(bob.session_id))
        .expect("bob should receive his own UserState");
    assert_eq!(bob_self_state.hash.as_deref(), Some(bob_self_hash.as_str()));

    let alice_bob_state = alice
        .recv_until(
            |message| matches!(message, Message::UserState(state) if state.session == Some(bob.session_id)),
            std::time::Duration::from_secs(2),
        )
        .await
        .or_else(|| {
            alice
                .initial_user_states
                .iter()
                .find(|state| state.session == Some(bob.session_id))
                .cloned()
                .map(Message::UserState)
        })
        .expect("alice should see bob");
    let Message::UserState(alice_bob_state) = alice_bob_state else {
        panic!("expected Bob UserState");
    };
    let expected = crate::privacy::protected_certificate_hash_hex(
        crate::config::CertificateHashProtection::Reversible,
        "test-shared-certificate-hash-secret",
        &bob_self_hash,
    )
    .expect("valid test hash");
    assert_eq!(alice_bob_state.hash.as_deref(), Some(expected.as_str()));
    assert_ne!(
        alice_bob_state.hash.as_deref(),
        Some(bob_self_hash.as_str())
    );
}

/// Checks that two users authenticating at the same time converge on each
/// other's presence even if one user's auth burst races the other's publish.
#[tokio::test]
async fn auth_concurrent_clients_see_each_other() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let (alice, bob) = tokio::join!(
        TestClient::connect_and_authenticate(&server, "alice", None),
        TestClient::connect_and_authenticate(&server, "bob", None),
    );
    let alice = alice.expect("alice auth");
    let bob = bob.expect("bob auth");

    assert_peer_seen_exactly_once(&alice, bob.session_id, "Alice", "Bob").await;
    assert_peer_seen_exactly_once(&bob, alice.session_id, "Bob", "Alice").await;
}

async fn assert_peer_seen_exactly_once(
    viewer: &TestClient,
    peer_session_id: u32,
    viewer_name: &str,
    peer_name: &str,
) {
    let mut seen = viewer
        .initial_user_states
        .iter()
        .filter(|state| is_join_snapshot_for_session(state, peer_session_id))
        .count();

    if seen == 0 {
        let saw_peer = viewer
            .recv_until(
                |message| {
                    matches!(message, Message::UserState(state) if is_join_snapshot_for_session(state, peer_session_id))
                },
                std::time::Duration::from_secs(2),
            )
            .await;
        assert!(
            saw_peer.is_some(),
            "{viewer_name} should receive {peer_name}'s UserState"
        );
        seen += 1;
    }

    let duplicate = viewer
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state) if is_join_snapshot_for_session(state, peer_session_id))
            },
            std::time::Duration::from_millis(100),
        )
        .await;
    assert!(
        duplicate.is_none(),
        "{viewer_name} should not receive duplicate {peer_name} UserState during concurrent auth"
    );
    assert_eq!(
        seen, 1,
        "{viewer_name} should see exactly one initial/live {peer_name} UserState"
    );
}

fn is_join_snapshot_for_session(state: &crate::mumble_proto::UserState, session_id: u32) -> bool {
    state.session == Some(session_id) && state.name.is_some() && state.channel_id.is_some()
}

#[tokio::test]
async fn auth_initial_snapshot_ignores_authenticated_unpublished_clients() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("observer", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("late", None, Some(2), vec![]);

    let (web_tx, _web_rx) = tokio::sync::mpsc::channel(1);
    let pending = server
        .server
        .get_clients()
        .allocate_web_client(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 30_001)),
            server.addr,
            web_tx,
        )
        .await;
    {
        let mut state = pending.write_global_state_direct();
        state.set_user_id(Some(99));
        state.set_display_name(Some("pending".to_owned()));
        state.set_current_channel_id(0);
    }
    pending.set_authenticated(true);
    pending.set_published(false);

    assert!(
        pending.is_authenticated(),
        "fixture must model post-auth state"
    );
    assert!(
        !pending.is_published(),
        "fixture must model the pre-AddClient publish window"
    );
    let pending_session = pending.get_session_id();

    let observer = TestClient::connect_and_authenticate(&server, "observer", None)
        .await
        .expect("observer auth");
    assert!(
        observer
            .initial_user_states
            .iter()
            .all(|state| state.session != Some(u32::from(pending_session))),
        "initial auth snapshot must not include authenticated clients before AddClient publish"
    );

    server
        .server
        .get_clients()
        .publish_client(pending_session)
        .await;
    let published_state = observer
        .recv_until(
            |message| matches!(message, Message::UserState(state) if state.session == Some(u32::from(pending_session))),
            std::time::Duration::from_secs(2),
        )
        .await;
    assert!(
        published_state.is_some(),
        "published client should still arrive through AddClient replay/broadcast"
    );

    let late = TestClient::connect_and_authenticate(&server, "late", None)
        .await
        .expect("late auth");
    assert!(
        late.initial_user_states
            .iter()
            .any(|state| state.session == Some(u32::from(pending_session))),
        "clients that authenticate after AddClient publish should include the peer in their initial snapshot"
    );
}

#[tokio::test]
async fn auth_selected_server_id_absent_from_config_scopes_client() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_user_in_server(
        "alice",
        None,
        Some(1),
        vec![],
        Language::default(),
        Some("tenant-auth"),
    );

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");

    assert_eq!(server.server.get_clients().local_len().await, 1);
    assert_eq!(
        server
            .server
            .get_clients()
            .local_len_in_server("tenant-auth")
            .await,
        1
    );
    assert_eq!(
        server
            .server
            .get_clients()
            .local_len_in_server(crate::types::DEFAULT_SERVER_ID)
            .await,
        0
    );
    assert!(
        server
            .server
            .get_clients()
            .get_client_in_server("tenant-auth", alice.server_session)
            .await
            .is_some()
    );
}

#[tokio::test]
async fn context_action_modify_from_client_closes_connection() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");

    alice
        .send(
            ContextActionModify {
                action: "server-only".to_string(),
                text: Some("Server only".to_string()),
                context: Some(0),
                operation: Some(0),
            }
            .into(),
        )
        .await;

    assert!(
        alice.recv_closed(std::time::Duration::from_secs(2)).await,
        "client-sent ContextActionModify should close the connection"
    );
}

#[tokio::test]
async fn auth_server_sync_reports_evaluated_root_permissions() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    server
        .server
        .get_channels()
        .set_acls(
            0,
            true,
            vec![ACL {
                user_id: None,
                group: Some("all".to_owned()),
                apply_here: true,
                apply_subs: true,
                allow: enumflags2::BitFlags::empty(),
                deny: ACLPermissions::TextMessage.into(),
            }],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob auth");

    let expected = (ACLPermissions::Traverse
        | ACLPermissions::Enter
        | ACLPermissions::Speak
        | ACLPermissions::Whisper
        | ACLPermissions::Listen)
        .bits();
    assert_eq!(bob.initial_permissions, Some(u64::from(expected)));
}

#[tokio::test]
async fn auth_max_bandwidth_override_is_reported_in_server_sync() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_user_with_max_bandwidth(
        "alice",
        None,
        Some(1),
        vec![],
        Some(24_000),
    );

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");

    assert_eq!(alice.max_bandwidth, Some(24_000));
}

/// Checks that a registered user with the wrong password is rejected.
/// Expected: authentication fails with `Reject::WrongUserPw`, matching
/// Mumble's reject mapping in `D:\mumble\src\murmur\Messages.cpp::msgAuthenticate`
/// and shitspeak's `RejectAuth` use from `D:\shitspeak\server.go::handleAuthenticate`.
#[tokio::test]
async fn auth_wrong_password_rejected() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", Some("hunter2"), Some(1), vec![]);

    match TestClient::connect_and_authenticate(&server, "alice", Some("nope")).await {
        Err(crate::integration_tests::harness::test_client::ConnectError::Rejected(r)) => {
            assert_eq!(r.r#type, Some(RejectType::WrongUserPw as i32));
        }
        Err(other) => panic!("expected Rejected, got {other:?}"),
        Ok(_) => panic!("auth should have failed"),
    }
    assert_eq!(server.authenticator.authenticate_call_count("alice"), 1);
}

#[tokio::test]
async fn auth_wrong_password_uses_default_unauthenticated_language() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_user_with_language(
        "alice",
        Some("hunter2"),
        Some(1),
        vec![],
        Language::Spanish,
    );

    match TestClient::connect_and_authenticate(&server, "alice", Some("nope")).await {
        Err(crate::integration_tests::harness::test_client::ConnectError::Rejected(r)) => {
            assert_eq!(r.r#type, Some(RejectType::WrongUserPw as i32));
            assert_eq!(r.reason.as_deref(), Some("Incorrect username or password"));
        }
        Err(other) => panic!("expected Rejected, got {other:?}"),
        Ok(_) => panic!("auth should have failed"),
    }
}

/// Checks that an unknown username is not allowed to authenticate.
/// Expected: authentication fails with `Reject::InvalidUsername`, as defined by
/// `D:\mumble\src\Mumble.proto` and emitted by Mumble's `msgAuthenticate`; the
/// same user-validation rejection is mirrored in `D:\shitspeak\server.go::handleAuthenticate`.
#[tokio::test]
async fn auth_unknown_user_rejected() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    // No users registered.

    match TestClient::connect_and_authenticate(&server, "ghost", None).await {
        Err(crate::integration_tests::harness::test_client::ConnectError::Rejected(r)) => {
            assert_eq!(r.r#type, Some(RejectType::InvalidUsername as i32));
        }
        Err(other) => panic!("expected Rejected, got {other:?}"),
        Ok(_) => panic!("auth should have failed"),
    }
}

/// Checks that the server enforces its configured maximum authenticated users.
/// Expected: once the server is full, the next login receives
/// `Reject::ServerFull`. This comes from Mumble's capacity check in
/// `D:\mumble\src\murmur\Messages.cpp::msgAuthenticate` and shitspeak's
/// max-client check before auth completion in `D:\shitspeak\client.go`.
#[tokio::test]
async fn auth_server_full_rejected() {
    let server = spawn_test_server(TestServerOpts {
        max_users: 2,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("charlie", None, Some(3), vec![]);

    let _alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");
    let _bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob auth");

    match TestClient::connect_and_authenticate(&server, "charlie", None).await {
        Err(crate::integration_tests::harness::test_client::ConnectError::Rejected(r)) => {
            assert_eq!(r.r#type, Some(RejectType::ServerFull as i32));
        }
        Err(other) => panic!("expected Rejected, got {other:?}"),
        Ok(_) => panic!("charlie auth should have failed (server full)"),
    }
}

/// Checks certificate-required authentication without a client certificate.
/// Expected: the login is rejected with `Reject::NoCertificate`, following
/// Mumble's `certrequired` branch in `D:\mumble\src\murmur\Messages.cpp::msgAuthenticate`
/// and shitspeak's certificate gate in `D:\shitspeak\server.go::handleAuthenticate`.
#[tokio::test]
async fn auth_no_cert_when_required_rejected() {
    let server = spawn_test_server(TestServerOpts {
        cert_required: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    match TestClient::connect_without_cert(&server, "alice", None).await {
        Err(crate::integration_tests::harness::test_client::ConnectError::Rejected(r)) => {
            assert_eq!(r.r#type, Some(RejectType::NoCertificate as i32));
        }
        Err(other) => panic!("expected Rejected, got {other:?}"),
        Ok(_) => panic!("auth should have failed (no cert)"),
    }
}

#[tokio::test]
async fn permission_denied_uses_authenticated_language() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_user_with_language(
        "alice",
        None,
        Some(1),
        vec![],
        Language::Spanish,
    );

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    alice.move_to_channel(99).await;

    let denied = alice
        .recv_until(
            |m| matches!(m, Message::PermissionDenied(pd) if pd.channel_id == Some(99)),
            std::time::Duration::from_secs(2),
        )
        .await;

    let Some(Message::PermissionDenied(pd)) = denied else {
        panic!("Alice should receive PermissionDenied");
    };
    assert_eq!(pd.reason.as_deref(), Some("El canal 99 no existe"));
}
