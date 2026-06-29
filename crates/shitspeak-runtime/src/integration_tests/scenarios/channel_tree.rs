//! Channel-tree rendering scenarios: BFS burst on login, and live propagation
//! of channel create/remove broadcasts to other connected clients.

use std::time::Duration;

use crate::channels::Channel;
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::messages::Message;

/// Checks that the login channel-tree burst contains every existing channel.
/// Expected: the authenticated client receives `ChannelState` entries for
/// root and all pre-created children. Mumble sends this burst during
/// `D:\mumble\src\murmur\Messages.cpp::msgAuthenticate`; shitspeak mirrors the
/// initial tree sync in its authenticate path in `D:\shitspeak\server.go`.
#[tokio::test]
async fn tree_burst_includes_all_channels() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    // Pre-populate a small channel tree:
    //   root (0)
    //   ├── general (1)
    //   └── lobby (2)
    //       └── corner (3)
    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(1, "general".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(2, "lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(3, "corner".to_owned(), 0, 0, Some(2)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice auth");

    let ids: Vec<u32> = alice
        .initial_channel_states
        .iter()
        .filter_map(|cs| cs.channel_id)
        .collect();
    for expected in [0, 1, 2, 3] {
        assert!(
            ids.contains(&expected),
            "expected channel id {expected} in burst, got {ids:?}"
        );
    }

    let names: Vec<&str> = alice
        .initial_channel_states
        .iter()
        .filter_map(|cs| cs.name.as_deref())
        .collect();
    for expected in ["general", "lobby", "corner"] {
        assert!(
            names.iter().any(|n| *n == expected),
            "expected channel name {expected:?}, got {names:?}"
        );
    }
}

/// Checks that a post-login channel creation reaches already-connected peers.
/// Expected: Bob receives a `ChannelState` named `lobby`. This follows the
/// Mumble `ChannelState` create/broadcast behavior in `D:\mumble\src\murmur\Messages.cpp`
/// and shitspeak's `D:\shitspeak\message.go::handleChannelStateMessage`.
#[tokio::test]
async fn tree_create_propagates_to_peer() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.create_channel(0, "lobby", false).await;

    let msg = bob
        .recv_until(
            |m| {
                matches!(
                    m,
                    Message::ChannelState(cs)
                        if cs.name.as_deref() == Some("lobby")
                )
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have received the new channel state"
    );
}

/// Checks that removing a channel reaches already-connected peers.
/// Expected: Bob receives `ChannelRemove` for the deleted channel id. The
/// expected behavior comes from Mumble's `ChannelRemove` message and
/// `D:\mumble\src\murmur\Messages.cpp::msgChannelRemove`, mirrored by
/// `D:\shitspeak\message.go::handleChannelRemoveMessage`.
#[tokio::test]
async fn tree_remove_propagates_to_peer() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(7, "doomed".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.remove_channel(7).await;

    let msg = bob
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == 7),
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have received ChannelRemove for channel 7"
    );
}
