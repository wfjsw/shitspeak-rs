//! Channel CRUD scenarios.

use std::time::Duration;

use crate::channels::Channel;
use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::messages::Message;

#[tokio::test]
async fn create_permanent_channel_propagates() {
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

    alice.create_channel(0, "Lobby", false).await;

    let saw_alice = alice
        .recv_until(
            |m| matches!(m, Message::ChannelState(cs) if cs.name.as_deref() == Some("Lobby")),
            Duration::from_secs(2),
        )
        .await;
    let saw_bob = bob
        .recv_until(
            |m| matches!(m, Message::ChannelState(cs) if cs.name.as_deref() == Some("Lobby")),
            Duration::from_secs(2),
        )
        .await;
    assert!(saw_alice.is_some(), "Alice should observe her own creation");
    assert!(saw_bob.is_some(), "Bob should observe Alice's creation");
}

#[tokio::test]
async fn update_channel_name_propagates() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(11, "Old".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.update_channel_name(11, "Renamed").await;

    let saw_bob = bob
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.channel_id == Some(11) && cs.name.as_deref() == Some("Renamed"))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(saw_bob.is_some(), "Bob should see the renamed channel");
}

#[tokio::test]
async fn remove_channel_migrates_users_to_parent() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(20, "Doomed".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(20).await;
    // Wait for bob's move to land before removing the channel.
    let _ = alice
        .recv_until(
            |m| matches!(m, Message::UserState(us) if us.channel_id == Some(20)),
            Duration::from_secs(2),
        )
        .await;

    alice.remove_channel(20).await;

    // Bob should be migrated back to root (channel 0).
    let bob_session = bob.session_id;
    let saw_alice = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.channel_id == Some(0))
            },
            Duration::from_secs(3),
        )
        .await;
    assert!(
        saw_alice.is_some(),
        "Alice should observe Bob being migrated back to root after channel 20 was removed"
    );
}
