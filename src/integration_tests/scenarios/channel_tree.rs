//! Channel-tree rendering scenarios: BFS burst on login, and live propagation
//! of channel create/remove broadcasts to other connected clients.

use std::time::Duration;

use crate::channels::Channel;
use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::messages::Message;

#[tokio::test]
async fn tree_burst_includes_all_channels() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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

#[tokio::test]
async fn tree_create_propagates_to_peer() {
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

#[tokio::test]
async fn tree_remove_propagates_to_peer() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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
