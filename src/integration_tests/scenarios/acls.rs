//! ACL scenarios: write an ACL that denies Enter on a sub-channel; the
//! restricted client gets a `PermissionDenied` and stays in their original
//! channel.

use std::time::Duration;

use crate::acl::ACLPermissions;
use crate::channels::Channel;
use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::messages::encoder::ChanAcl;
use crate::messages::Message;

#[tokio::test]
async fn acl_denies_enter_for_non_admin() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    // Pre-create a "Private" sub-channel under root.
    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(40, "Private".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    // Alice (superuser/admin) writes an ACL on channel 40 that denies Enter
    // to the implicit "all" group. (Members of "admin" still pass via the
    // is_superuser bypass.)
    let acls = vec![ChanAcl {
        apply_here: true,
        apply_subs: false,
        inherited: false,
        user_id: None,
        group: Some("all".to_owned()),
        grant: 0,
        deny: ACLPermissions::Enter as u32,
    }];
    alice.set_acls(40, acls, true).await;

    // Give the ACL update a moment to commit.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob attempts to move into the private channel.
    let bob_session = bob.session_id;
    bob.move_to_channel(40).await;

    let denied = bob
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.channel_id == Some(40))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        denied.is_some(),
        "Bob should have received PermissionDenied for channel 40"
    );

    // And Bob should NOT have a UserState saying he's in channel 40.
    let moved = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.channel_id == Some(40))
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(moved.is_none(), "Bob should NOT have moved into channel 40");
}

#[tokio::test]
async fn acl_query_returns_chain() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(41, "Pub".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let acls = vec![ChanAcl {
        apply_here: true,
        apply_subs: false,
        inherited: false,
        user_id: None,
        group: Some("all".to_owned()),
        grant: ACLPermissions::Speak as u32,
        deny: 0,
    }];
    alice.set_acls(41, acls, true).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    alice.query_acls(41).await;

    let resp = alice
        .recv_until(
            |m| matches!(m, Message::ACL(a) if a.channel_id == 41),
            Duration::from_secs(2),
        )
        .await;
    assert!(
        resp.is_some(),
        "Alice should receive an ACL response for channel 41"
    );
}
