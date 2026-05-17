//! Self-actions: self-mute / self-deaf / comment broadcast to peers.

use std::time::Duration;

use bytes::Bytes;

use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::messages::Message;

/// Checks that self-mute changes are broadcast to peers.
/// Expected: Bob receives Alice's `UserState` with `self_mute = true`. This is
/// Mumble's self-state update behavior in `D:\mumble\src\murmur\Messages.cpp::msgUserState`
/// and shitspeak's equivalent in `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn self_mute_broadcasts() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.set_self_mute(true).await;

    let alice_session = alice.session_id;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session) && us.self_mute == Some(true))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have seen Alice's self_mute=true UserState"
    );
}

/// Checks that self-deaf changes are broadcast to peers.
/// Expected: Bob receives Alice's `UserState` with `self_deaf = true`; Mumble
/// also treats deaf as implying mute in `msgUserState`. The expected behavior
/// comes from `D:\mumble\src\murmur\Messages.cpp::msgUserState` and
/// `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn self_deaf_broadcasts() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.set_self_deaf(true).await;

    let alice_session = alice.session_id;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session) && us.self_deaf == Some(true))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have seen Alice's self_deaf=true UserState"
    );
}

/// Checks that comment updates are advertised by blob hash and retrievable.
/// Expected: Bob receives Alice's `UserState` with `comment_hash`, then a
/// `RequestBlob` for Alice's session returns the original comment text.
#[tokio::test]
async fn self_comment_blob_broadcasts_and_fetches() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let comment = "alice profile comment";
    alice.set_comment(comment).await;

    let alice_session = alice.session_id;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.comment.is_none()
                        && us.comment_hash.as_ref().is_some_and(|hash| hash.len() == 20))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have seen Alice's comment_hash UserState"
    );

    bob.request_session_comment(alice_session).await;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.comment.as_deref() == Some(comment))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have fetched Alice's comment blob"
    );

    alice.set_comment("").await;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.comment.as_deref() == Some(""))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(msg.is_some(), "Bob should have seen Alice clear comment");
}

/// Checks that texture updates are advertised by blob hash and retrievable.
/// Expected: Bob receives Alice's `UserState` with `texture_hash`, then a
/// `RequestBlob` for Alice's session returns the original texture bytes.
#[tokio::test]
async fn self_texture_blob_broadcasts_and_fetches() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let texture = Bytes::from_static(b"\x89PNG\r\n\x1a\ntexture-bytes");
    alice.set_texture(texture.clone()).await;

    let alice_session = alice.session_id;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.texture.is_none()
                        && us.texture_hash.as_ref().is_some_and(|hash| hash.len() == 20))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have seen Alice's texture_hash UserState"
    );

    bob.request_session_texture(alice_session).await;
    let expected_texture = texture.to_vec();
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.texture.as_ref() == Some(&expected_texture))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have fetched Alice's texture blob"
    );

    alice.set_texture(Bytes::new()).await;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.texture.as_ref().is_some_and(Vec::is_empty))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(msg.is_some(), "Bob should have seen Alice clear texture");
}
