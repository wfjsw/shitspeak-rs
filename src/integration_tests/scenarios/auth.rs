//! Auth-flow scenarios: success, wrong password, unknown user, server full,
//! and `cert_required` rejection.

use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::messages::encoder::RejectType;

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
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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

    // Both clients receive the welcome text we configured.
    assert_eq!(alice.welcome_text.as_deref(), Some("test-welcome"));
    assert_eq!(bob.welcome_text.as_deref(), Some("test-welcome"));
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
