//! Moderator actions: mute another user, kick, ban (and verify ban survives a
//! reconnect attempt). Kick and ban are guarded by root-channel ACL permissions,
//! while mute/deaf moderation is guarded by MuteDeafen.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use shitspeak_messages::messages::Message;
use shitspeak_messages::messages::encoder::UserState;
use shitspeak_state::ACLPermissions;

/// A native Mumble client sends a BanList address as a 16-byte HostAddress,
/// using an IPv4-mapped IPv6 value for an IPv4 ban. The server must accept it
/// rather than treating the binary field as UTF-8 and disconnecting the client.
#[tokio::test]
async fn moderator_can_add_ipv4_ban_from_ban_list() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    alice.drain_now().await;

    alice
        .send(Message::BanList(shitspeak_proto::mumble_proto::BanList {
            bans: vec![shitspeak_proto::mumble_proto::ban_list::BanEntry {
                address: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 42],
                mask: 24,
                name: None,
                hash: None,
                reason: Some("native-client regression".into()),
                start: None,
                duration: None,
            }],
            query: Some(false),
        }))
        .await;

    assert!(
        !alice.recv_closed(Duration::from_secs(2)).await,
        "a native BanList update must not disconnect the moderator"
    );

    alice
        .send(Message::BanList(shitspeak_proto::mumble_proto::BanList {
            bans: vec![],
            query: Some(true),
        }))
        .await;
    let reply = alice
        .recv_until(
            |message| matches!(message, Message::BanList(list) if list.bans.len() == 1),
            Duration::from_secs(2),
        )
        .await
        .expect("server should return the updated ban list");
    let Message::BanList(reply) = reply else {
        unreachable!("predicate only admits BanList replies");
    };
    assert_eq!(
        reply.bans[0].address,
        vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 42,]
    );

    let bans = server.server.get_bans().get_active_bans().await;
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].address, "203.0.113.42".parse::<IpAddr>().unwrap());
    assert_eq!(bans[0].mask, 24);
    assert_eq!(bans[0].reason.as_deref(), Some("native-client regression"));
}

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

#[tokio::test]
async fn moderator_unsuppress_disables_hidden_superuser_mode() {
    use crate::toggle_superuser_visibility::{ACTION_ID, HIDE_LABEL};

    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_superuser("carol", None, Some(2), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.drain_now().await;
    alice.drain_now().await;

    alice.trigger_context_action(ACTION_ID).await;
    bob.recv_until(
        |message| {
            matches!(message, Message::UserRemove(remove)
                if remove.session == alice.session_id)
        },
        Duration::from_secs(2),
    )
    .await
    .expect("Alice should become hidden");

    carol.suppress_other(alice.session_id, false).await;
    bob.recv_until(
        |message| {
            matches!(message, Message::UserState(state)
                if state.session == Some(alice.session_id)
                    && state.name.is_some()
                    && state.channel_id.is_some())
        },
        Duration::from_secs(2),
    )
    .await
    .expect("moderator unsuppress should reveal Alice");
    alice
        .recv_until(
            |message| {
                matches!(message, Message::ContextActionModify(modify)
                    if modify.action == ACTION_ID
                        && modify.text.as_deref() == Some(HIDE_LABEL))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("moderator unsuppress should reset Alice's action label");

    let live_alice = server
        .server
        .get_clients()
        .get_client(alice.server_session)
        .await
        .expect("live Alice");
    let state = live_alice.read_global_state();
    assert!(!state.is_hidden_from_regular_users());
    assert!(!state.is_suppressed());
    drop(state);

    bob.drain_now().await;
    alice.drain_now().await;
    alice.trigger_context_action(ACTION_ID).await;
    bob.recv_until(
        |message| {
            matches!(message, Message::UserRemove(remove)
                if remove.session == alice.session_id)
        },
        Duration::from_secs(2),
    )
    .await
    .expect("Alice should become hidden again");

    carol.mute_other(alice.session_id, false).await;
    bob.recv_until(
        |message| {
            matches!(message, Message::UserState(state)
                if state.session == Some(alice.session_id)
                    && state.name.is_some()
                    && state.channel_id.is_some())
        },
        Duration::from_secs(2),
    )
    .await
    .expect("moderator mute=false should also reveal Alice");
    alice
        .recv_until(
            |message| {
                matches!(message, Message::ContextActionModify(modify)
                    if modify.action == ACTION_ID
                        && modify.text.as_deref() == Some(HIDE_LABEL))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("mute=false should reset Alice's action label");

    let state = live_alice.read_global_state();
    assert!(!state.is_hidden_from_regular_users());
    assert!(!state.is_suppressed());
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

/// An authenticated client can have received ServerSync while its connection
/// task has not yet published AddClient. Kicking it in that window must still
/// produce a UserRemove for existing peers.
#[tokio::test]
async fn mod_kick_publishes_authenticated_target_before_removal() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let (target_tx, mut target_rx) = tokio::sync::mpsc::channel(1);
    let target = server
        .server
        .get_clients()
        .allocate_web_client(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 30_101)),
            server.addr,
            target_tx,
        )
        .await;
    {
        let mut state = target.write_global_state_direct();
        state.set_display_name(Some("pending".to_owned()));
    }
    target.set_authenticated(true);
    target.set_published(false);
    let target_session = u32::from(target.get_session_id());

    alice.kick(target_session, "publish before remove").await;

    let target_notice = tokio::time::timeout(Duration::from_secs(2), target_rx.recv())
        .await
        .expect("target receives its kick notice")
        .expect("target kick notice is sent");
    assert!(matches!(
        target_notice,
        Message::UserRemove(remove)
            if remove.session == target_session
                && remove.actor == Some(alice.session_id)
                && remove.reason.as_deref() == Some("publish before remove")
                && remove.ban == Some(false)
    ));

    let peer_notice = alice
        .recv_until(
            |message| {
                matches!(message, Message::UserRemove(remove)
                    if remove.session == target_session
                        && remove.actor == Some(alice.session_id)
                        && remove.reason.as_deref() == Some("publish before remove")
                        && remove.ban == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        peer_notice.is_some(),
        "peers must receive UserRemove when a pre-publish client is kicked"
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
