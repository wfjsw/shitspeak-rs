//! Channel-move scenarios: self-move and moderator-move both produce a
//! UserState broadcast that the other client observes.

use std::time::Duration;

use crate::channels::Channel;
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::messages::Message;

/// Checks that a user's own channel move is broadcast to other clients.
/// Expected: Alice receives Bob's `UserState` with the new channel id. This is
/// the Mumble `UserState.channel_id` move behavior implemented in
/// `D:\mumble\src\murmur\Messages.cpp::msgUserState` and mirrored by
/// `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn self_move_broadcasts_to_peer() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(30, "Lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(30).await;

    let bob_session = bob.session_id;
    let saw = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.channel_id == Some(30))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(saw.is_some(), "Alice should see Bob's self-move to lobby");
}

/// Checks that a moderator can move another user and the target sees the move.
/// Expected: Bob receives a `UserState` placing his own session in the target
/// channel. Mumble implements this as a privileged `UserState` update in
/// `D:\mumble\src\murmur\Messages.cpp::msgUserState`; shitspeak follows the
/// same permission and broadcast path in `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn moderator_move_other() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(31, "Lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let bob_session = bob.session_id;
    alice.move_other(bob_session, 31).await;

    let saw_bob = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.channel_id == Some(31))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        saw_bob.is_some(),
        "Bob should see his channel update after moderator move"
    );
}
