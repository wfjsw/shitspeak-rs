//! Moderator actions: mute another user, kick, ban (and verify ban survives a
//! reconnect attempt). Kick and ban are guarded by root-channel ACL permissions,
//! while mute/deaf moderation is guarded by MuteDeafen.

use std::time::Duration;

use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::messages::Message;
use crate::messages::encoder::UserState;
use shitspeak_state::ACLPermissions;

/// Checks that a moderator mute is applied to another user.
/// Expected: Bob receives `UserState { mute: true }` for his session. Mumble
/// implements admin mute/deaf updates in `D:\mumble\src\murmur\Messages.cpp::msgUserState`;
/// shitspeak mirrors the permission and broadcast behavior in
/// `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn mod_mutes_other() {
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
async fn superuser_can_unsuppress_other() {
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

    let live_bob = server
        .server
        .get_clients()
        .get_client(bob.server_session)
        .await
        .expect("live bob");
    {
        let mut gs = live_bob.write_global_state_direct();
        gs.set_suppress(true);
    }

    let mut state = UserState::default();
    state.session = Some(bob.server_session);
    state.suppress = Some(false);
    alice.send(state.into()).await;

    let cleared = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.suppress == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        cleared.is_some(),
        "superuser should be able to unsuppress Bob"
    );

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.permission == Some(ACLPermissions::MuteDeafen as u32))
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(
        denied.is_none(),
        "unsuppress should not report missing MuteDeafen to a superuser"
    );
}

/// Checks that a moderator kick removes the target from the server.
/// Expected: Alice receives `UserRemove` for Bob's session. This comes from
/// Mumble's kick path in `D:\mumble\src\murmur\Messages.cpp::msgUserRemove`
/// and the `UserRemove` proto semantics; shitspeak implements the same path in
/// `D:\shitspeak\message.go::handleUserRemoveMessage`.
#[tokio::test]
async fn mod_kicks_other() {
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

    let bob_session = bob.session_id;
    let kick_reason = "test";
    alice.kick(bob_session, kick_reason).await;

    let bob_observed = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserRemove(ur)
                    if ur.session == bob_session
                        && ur.actor == Some(alice.session_id)
                        && ur.reason.as_deref() == Some(kick_reason)
                        && ur.ban == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        bob_observed.is_some(),
        "Bob should receive the kick reason before disconnect"
    );

    assert!(
        bob.recv_closed(Duration::from_secs(2)).await,
        "Bob's TCP connection should close immediately after kick"
    );

    // Alice should see UserRemove for Bob's session.
    let alice_observed = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserRemove(ur)
                    if ur.session == bob_session
                        && ur.actor == Some(alice.session_id)
                        && ur.reason.as_deref() == Some(kick_reason)
                        && ur.ban == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        alice_observed.is_some(),
        "Alice should have received UserRemove for Bob"
    );
}

/// Checks that a user without root Kick permission cannot kick another user.
#[tokio::test]
async fn non_mod_cannot_kick_other() {
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

    let bob_session = bob.session_id;
    alice.kick(bob_session, "test").await;

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.channel_id == Some(0)
                        && pd.permission == Some(ACLPermissions::Kick as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(denied.is_some(), "Alice should be denied Kick on root");

    let removed = alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == bob_session),
            Duration::from_millis(300),
        )
        .await;
    assert!(removed.is_none(), "Bob should not be kicked");
}

/// Checks that a moderator ban records a server ban entry after removing a user.
/// Expected: the ban repository contains an active entry after Alice bans Bob.
/// Mumble's behavior is defined by `UserRemove.ban` and ban persistence in
/// `D:\mumble\src\murmur\Messages.cpp::msgUserRemove`; shitspeak mirrors this
/// in `D:\shitspeak\message.go::handleUserRemoveMessage` and `D:\shitspeak\ban.go`.
#[tokio::test]
async fn mod_bans_other_blocks_reconnect() {
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

    let bob_session = bob.session_id;
    let ban_reason = "banned for the test";
    alice.ban(bob_session, ban_reason).await;

    let bob_observed = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserRemove(ur)
                    if ur.session == bob_session
                        && ur.actor == Some(alice.session_id)
                        && ur.reason.as_deref() == Some(ban_reason)
                        && ur.ban == Some(true))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        bob_observed.is_some(),
        "Bob should receive the ban reason before disconnect"
    );
    assert!(
        bob.recv_closed(Duration::from_secs(2)).await,
        "Bob's TCP connection should close immediately after ban"
    );

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

/// Checks that a user without root Ban permission cannot ban another user.
#[tokio::test]
async fn non_mod_cannot_ban_other() {
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

    let bob_session = bob.session_id;
    alice.ban(bob_session, "test").await;

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.channel_id == Some(0)
                        && pd.permission == Some(ACLPermissions::Ban as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(denied.is_some(), "Alice should be denied Ban on root");

    let removed = alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == bob_session),
            Duration::from_millis(300),
        )
        .await;
    assert!(
        removed.is_none(),
        "Bob should not be removed by a denied ban"
    );

    let bans = server.server.get_bans().get_active_bans().await;
    assert!(bans.is_empty(), "Denied ban should not create a ban entry");
}
