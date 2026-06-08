//! Auth-flow scenarios: success, wrong password, unknown user, server full,
//! and `cert_required` rejection.

use crate::acl::{ACL, ACLPermissions};
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::localization::Language;
use crate::messages::Message;
use crate::messages::encoder::{ContextActionModify, RejectType};

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

/// Checks that two users authenticating at the same time converge on each
/// other's presence even if one user's auth burst races the other's publish.
#[tokio::test]
async fn auth_concurrent_clients_see_each_other() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let (alice, bob) = tokio::join!(
        TestClient::connect_and_authenticate(&server, "alice", None),
        TestClient::connect_and_authenticate(&server, "bob", None),
    );
    let alice = alice.expect("alice auth");
    let bob = bob.expect("bob auth");

    let alice_saw_bob_initial = alice
        .initial_user_states
        .iter()
        .any(|state| state.session == Some(bob.session_id));
    if !alice_saw_bob_initial {
        let saw_bob = alice
            .recv_until(
                |message| matches!(message, Message::UserState(state) if state.session == Some(bob.session_id)),
                std::time::Duration::from_secs(2),
            )
            .await;
        assert!(saw_bob.is_some(), "Alice should receive Bob's UserState");
    }

    let bob_saw_alice_initial = bob
        .initial_user_states
        .iter()
        .any(|state| state.session == Some(alice.session_id));
    if !bob_saw_alice_initial {
        let saw_alice = bob
            .recv_until(
                |message| matches!(message, Message::UserState(state) if state.session == Some(alice.session_id)),
                std::time::Duration::from_secs(2),
            )
            .await;
        assert!(saw_alice.is_some(), "Bob should receive Alice's UserState");
    }
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
}

#[tokio::test]
async fn auth_wrong_password_uses_authenticator_language() {
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
            assert_eq!(
                r.reason.as_deref(),
                Some("Usuario o contraseña incorrectos")
            );
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
