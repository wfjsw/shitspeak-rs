//! Channel CRUD scenarios.

use std::time::Duration;

use crate::acl::{ACL, ACLPermissions};
use crate::channels::Channel;
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::messages::Message;

/// Checks that creating a permanent channel is broadcast to all clients.
/// Expected: both creator and peer receive a `ChannelState` for the new
/// channel. This follows Mumble's `ChannelState` create path in
/// `D:\mumble\src\murmur\Messages.cpp::msgChannelState` and shitspeak's
/// `D:\shitspeak\message.go::handleChannelStateMessage`.
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
async fn temp_channel_create_requires_temp_channel_permission() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    server
        .server
        .get_channels()
        .set_acls(
            0,
            true,
            vec![ACL {
                user_id: Some(1),
                group: None,
                apply_here: true,
                apply_subs: false,
                allow: ACLPermissions::MakeChannel.into(),
                deny: ACLPermissions::TempChannel.into(),
            }],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    alice.create_channel(0, "DeniedTemp", true).await;

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.channel_id == Some(0)
                        && pd.permission == Some(ACLPermissions::TempChannel as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        denied.is_some(),
        "Temporary channel creation should require TempChannel"
    );
}

/// Checks that renaming an existing channel propagates to peers.
/// Expected: Bob receives `ChannelState { channel_id: 11, name: "Renamed" }`.
/// Mumble sends channel edits through `msgChannelState` in
/// `D:\mumble\src\murmur\Messages.cpp`; shitspeak mirrors that update/broadcast
/// path in `D:\shitspeak\message.go::handleChannelStateMessage`.
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

/// Checks that removing a channel migrates occupants to its parent.
/// Expected: Bob is moved back to root and Alice observes the resulting
/// `UserState`. This is the Murmur channel-removal behavior in
/// `D:\mumble\src\murmur\Messages.cpp::msgChannelRemove` and
/// `D:\mumble\src\murmur\Server.cpp`, with matching shitspeak handling in
/// `D:\shitspeak\message.go::handleChannelRemoveMessage`.
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
