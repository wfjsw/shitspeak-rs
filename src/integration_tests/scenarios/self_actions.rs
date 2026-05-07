//! Self-actions: self-mute / self-deaf / comment broadcast to peers.

use std::time::Duration;

use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::messages::Message;

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

// NOTE: A `set_comment_broadcasts` test would belong here, but
// `handle_user_state` currently has a TODO that simply clears the
// comment blob hash without storing the text or broadcasting a
// UserState containing the new comment. Add this test once the
// server actually persists and rebroadcasts comments.
