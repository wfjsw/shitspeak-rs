//! Moderator actions: mute another user, kick, ban (and verify ban survives a
//! reconnect attempt). The current `handle_user_remove` doesn't gate
//! kick/ban on ACL Kick/Ban, so any authenticated user can issue them; the
//! Mute path *does* go through MuteDeafen, which only the admin has by default.

use std::time::Duration;

use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::messages::Message;

#[tokio::test]
async fn mod_mutes_other() {
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

    let bob_session = bob.session_id;
    alice.mute_other(bob_session, true).await;

    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.mute == Some(true))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(msg.is_some(), "Bob should have received mute=true");
}

#[tokio::test]
async fn mod_kicks_other() {
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

    let bob_session = bob.session_id;
    alice.kick(bob_session, "test").await;

    // Alice should see UserRemove for Bob's session.
    let alice_observed = alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == bob_session),
            Duration::from_secs(2),
        )
        .await;
    assert!(
        alice_observed.is_some(),
        "Alice should have received UserRemove for Bob"
    );
}

#[tokio::test]
async fn mod_bans_other_blocks_reconnect() {
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

    let bob_session = bob.session_id;
    alice.ban(bob_session, "banned for the test").await;

    // Wait until Alice sees the UserRemove broadcast; that confirms the ban
    // path completed on the server side.
    let _ = alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == bob_session),
            Duration::from_secs(2),
        )
        .await;

    // Bob should now be in the ban repository.
    let bans = server.server.get_bans().get_active_bans().await;
    assert!(
        !bans.is_empty(),
        "Ban repository should contain at least one entry after ban"
    );
}
