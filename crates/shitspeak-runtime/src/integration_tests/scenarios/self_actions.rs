//! Self-actions: self-mute / self-deaf / comment broadcast to peers.

use std::time::Duration;

use bytes::Bytes;

use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use shitspeak_messages::messages::Message;
use shitspeak_messages::messages::encoder::UserState;
use shitspeak_state::{ACL, ACLPermissions};

/// Checks that self-mute changes are broadcast to peers.
/// Expected: Bob receives Alice's `UserState` with `self_mute = true`. This is
/// Mumble's self-state update behavior in `D:\mumble\src\murmur\Messages.cpp::msgUserState`
/// and shitspeak's equivalent in `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn self_mute_broadcasts() {
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

/// Checks that self-deaf changes are broadcast to peers.
/// Expected: Bob receives Alice's `UserState` with `self_deaf = true`; Mumble
/// also treats deaf as implying mute in `msgUserState`. The expected behavior
/// comes from `D:\mumble\src\murmur\Messages.cpp::msgUserState` and
/// `D:\shitspeak\message.go::handleUserStateMessage`.
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

#[tokio::test]
async fn pre_auth_user_state_only_updates_self_mute_deaf() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let mut pre_auth_state = UserState::default();
    pre_auth_state.self_deaf = Some(true);
    pre_auth_state.channel_id = Some(99);
    pre_auth_state.mute = Some(true);
    pre_auth_state.comment = Some("ignored before auth".into());

    let alice = TestClient::connect_with_preauth_messages(
        &server,
        "alice",
        None,
        vec![pre_auth_state.into()],
    )
    .await
    .expect("alice auth");

    let self_state = alice
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(alice.session_id))
        .expect("self UserState during auth sync");

    assert_eq!(self_state.self_deaf, Some(true));
    assert_eq!(self_state.self_mute, Some(true));
    assert_ne!(self_state.channel_id, Some(99));
    assert_eq!(self_state.mute, None);
    assert_eq!(self_state.comment, None);
}

#[tokio::test]
async fn self_priority_speaker_is_denied() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let mut state = UserState::default();
    state.session = Some(alice.server_session);
    state.priority_speaker = Some(true);
    alice.send(state.into()).await;

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.permission == Some(ACLPermissions::MuteDeafen as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(denied.is_some(), "Self priority speaker should be denied");
}

#[tokio::test]
async fn mute_deafen_user_can_set_own_priority_speaker() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .server
        .get_channels()
        .set_acls(
            0,
            true,
            vec![ACL {
                user_id: None,
                group: Some("all".to_owned()),
                apply_here: true,
                apply_subs: true,
                allow: ACLPermissions::MuteDeafen.into(),
                deny: enumflags2::BitFlags::empty(),
            }],
        )
        .await
        .unwrap();
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

    let mut state = UserState::default();
    state.session = Some(alice.server_session);
    state.priority_speaker = Some(true);
    alice.send(state.into()).await;

    let alice_session = alice.session_id;
    let granted = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.priority_speaker == Some(true))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        granted.is_some(),
        "MuteDeafen should allow setting own priority speaker"
    );
}

#[tokio::test]
async fn client_suppress_update_is_denied() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let mut state = UserState::default();
    state.session = Some(alice.server_session);
    state.suppress = Some(true);
    alice.send(state.into()).await;

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.permission == Some(ACLPermissions::MuteDeafen as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(denied.is_some(), "Client suppress updates should be denied");
}

#[tokio::test]
async fn mute_deafen_user_can_clear_own_server_mute_deaf_and_suppress() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .server
        .get_channels()
        .set_acls(
            0,
            true,
            vec![ACL {
                user_id: None,
                group: Some("all".to_owned()),
                apply_here: true,
                apply_subs: true,
                allow: ACLPermissions::MuteDeafen.into(),
                deny: enumflags2::BitFlags::empty(),
            }],
        )
        .await
        .unwrap();
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

    let live_alice = server
        .server
        .get_clients()
        .get_client(alice.server_session)
        .await
        .expect("live alice");
    {
        let mut gs = live_alice.write_global_state_direct();
        gs.set_mute(true);
        gs.set_deaf(true);
        gs.set_suppress(true);
    }

    let mut state = UserState::default();
    state.session = Some(alice.server_session);
    state.mute = Some(false);
    state.deaf = Some(false);
    state.suppress = Some(false);
    alice.send(state.into()).await;

    let cleared = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id)
                        && us.mute == Some(false)
                        && us.deaf == Some(false)
                        && us.suppress == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        cleared.is_some(),
        "MuteDeafen should allow clearing own server mute/deaf/suppress"
    );
}

/// Checks that comment updates are advertised by blob hash and retrievable.
/// Expected: Bob receives Alice's `UserState` with `comment_hash`, then a
/// `RequestBlob` for Alice's session returns the original comment text.
#[tokio::test]
async fn self_comment_blob_broadcasts_and_fetches() {
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

    let comment = "alice profile comment";
    alice.set_comment(comment).await;

    let alice_session = alice.session_id;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.comment.is_none()
                        && us.comment_hash.as_ref().is_some_and(|hash| hash.len() == 20))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have seen Alice's comment_hash UserState"
    );

    bob.request_session_comment(alice_session).await;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.comment.as_deref() == Some(comment))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have fetched Alice's comment blob"
    );

    alice.set_comment("").await;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.comment.as_deref() == Some(""))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(msg.is_some(), "Bob should have seen Alice clear comment");
}

/// Checks that texture updates are advertised by blob hash and retrievable.
/// Expected: Bob receives Alice's `UserState` with `texture_hash`, then a
/// `RequestBlob` for Alice's session returns the original texture bytes.
#[tokio::test]
async fn self_texture_blob_broadcasts_and_fetches() {
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

    let texture = Bytes::from_static(b"\x89PNG\r\n\x1a\ntexture-bytes");
    alice.set_texture(texture.clone()).await;

    let alice_session = alice.session_id;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.texture.is_none()
                        && us.texture_hash.as_ref().is_some_and(|hash| hash.len() == 20))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have seen Alice's texture_hash UserState"
    );

    bob.request_session_texture(alice_session).await;
    let expected_texture = texture.to_vec();
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.texture.as_ref() == Some(&expected_texture))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        msg.is_some(),
        "Bob should have fetched Alice's texture blob"
    );

    alice.set_texture(Bytes::new()).await;
    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && us.texture.as_ref().is_some_and(Vec::is_empty))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(msg.is_some(), "Bob should have seen Alice clear texture");
}
