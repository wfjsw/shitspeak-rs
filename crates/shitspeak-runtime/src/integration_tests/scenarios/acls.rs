//! ACL scenarios: write an ACL that denies Enter on a sub-channel; the
//! restricted client gets a `PermissionDenied` and stays in their original
//! channel.

use std::time::Duration;

use bytes::Bytes;

use crate::integration_tests::harness::{
    TestClient, TestServerOpts, spawn_test_server, test_user_channel_cache_key,
};
use shitspeak_messages::messages::Message;
use shitspeak_messages::messages::encoder::{
    Authenticate, CLIENT_PERMISSION_CACHE_BIT, ChanAcl, ClientType, PluginDataTransmission,
    TextMessage, UserState, UserStats, VoiceTarget,
};
use shitspeak_state::{ACL, ACLPermissions};
use shitspeak_state::{Channel, ChannelPatch};

/// Checks that ACL denial prevents a non-admin from entering a channel.
/// Expected: Bob receives `PermissionDenied` for the private channel and no
/// `UserState` moves him there. The behavior comes from Mumble ACL evaluation
/// in `D:\mumble\src\ACL.cpp` plus `Server::msgUserState`, and from
/// shitspeak's `D:\shitspeak\acl.go::CalculatePermission` and
/// `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn acl_denies_enter_for_non_admin() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
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

/// Checks that disabling debug ACL Enter bypass makes admins obey Enter ACLs.
/// Expected: Alice is an admin/superuser, but with `acl.debug_acl_enter =
/// false` she receives `PermissionDenied` for a channel that denies Enter to
/// `all`.
#[tokio::test]
async fn superuser_respects_enter_when_debug_acl_enter_disabled() {
    let server = spawn_test_server(TestServerOpts {
        debug_acl_enter: false,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(41, "Private".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            41,
            true,
            vec![ACL {
                user_id: None,
                group: Some("all".to_owned()),
                apply_here: true,
                apply_subs: false,
                allow: enumflags2::BitFlags::empty(),
                deny: ACLPermissions::Enter.into(),
            }],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let alice_session = alice.session_id;
    alice.move_to_channel(41).await;

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.channel_id == Some(41)
                        && pd.permission == Some(ACLPermissions::Enter as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        denied.is_some(),
        "Alice should have received PermissionDenied for channel 41"
    );

    let moved = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session) && us.channel_id == Some(41))
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(
        moved.is_none(),
        "Alice should NOT have moved into channel 41 when debug_acl_enter is false"
    );
}

/// Checks the default debug ACL behavior remains compatible with the prior
/// superuser bypass.
/// Expected: Alice is an admin/superuser and can enter a channel that denies
/// Enter to `all` while `acl.debug_acl_enter` is left at its default `true`.
#[tokio::test]
async fn superuser_ignores_enter_by_default() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(42, "Private".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            42,
            true,
            vec![ACL {
                user_id: None,
                group: Some("all".to_owned()),
                apply_here: true,
                apply_subs: false,
                allow: enumflags2::BitFlags::empty(),
                deny: ACLPermissions::Enter.into(),
            }],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let alice_session = alice.session_id;
    alice.move_to_channel(42).await;

    let moved = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session) && us.channel_id == Some(42))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        moved.is_some(),
        "Alice should have moved into channel 42 by default"
    );
}

/// Checks that querying ACLs returns the channel ACL chain after an update.
/// Expected: the server replies with an `ACL` message for the queried channel.
/// This follows Mumble's ACL request/reply protocol in `D:\mumble\src\Mumble.proto`
/// and Murmur ACL handling, mirrored by shitspeak's ACL store and query logic
/// in `D:\shitspeak\acl.go` and `D:\shitspeak\message.go`.
#[tokio::test]
async fn acl_query_returns_chain() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

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

#[tokio::test]
async fn superuser_acl_edit_does_not_add_personal_write_fallback() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(45, "SuperEdit".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    alice
        .set_acls(
            45,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: false,
                inherited: false,
                user_id: None,
                group: Some("all".to_owned()),
                grant: ACLPermissions::Speak as u32,
                deny: 0,
            }],
            true,
        )
        .await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let channel = chans.get_channel(45).await.expect("channel 45");
    assert_eq!(channel.acls.len(), 1);
    assert!(
        channel.acls.iter().all(|acl| acl.user_id != Some(1)),
        "superuser ACL edit should not add a personal Write fallback"
    );
}

#[tokio::test]
async fn preserve_write_acl_on_edit_flag_disables_personal_write_fallback() {
    let server = spawn_test_server(TestServerOpts {
        preserve_write_acl_on_edit: false,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(46, "NormalEdit".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            46,
            true,
            vec![ACL {
                user_id: Some(1),
                group: None,
                apply_here: true,
                apply_subs: false,
                allow: ACLPermissions::Write | ACLPermissions::Traverse,
                deny: enumflags2::BitFlags::empty(),
            }],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    alice.set_acls(46, Vec::new(), true).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let channel = chans.get_channel(46).await.expect("channel 46");
    assert!(
        channel.acls.is_empty(),
        "disabled preserve_write_acl_on_edit should let the ACL update remove the editor's Write"
    );
}

#[tokio::test]
async fn acl_query_returns_inherited_entries_before_local_entries() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(42, "Outer".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(43, "Middle".to_owned(), 0, 0, Some(42)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(44, "Inner".to_owned(), 0, 0, Some(43)))
        .await
        .unwrap();
    chans
        .set_acls(
            42,
            true,
            vec![acl_for_group(
                "outer",
                ACLPermissions::Traverse.into(),
                enumflags2::BitFlags::empty(),
                true,
            )],
        )
        .await
        .unwrap();
    chans
        .set_acls(
            43,
            true,
            vec![acl_for_group(
                "middle",
                ACLPermissions::Enter.into(),
                enumflags2::BitFlags::empty(),
                true,
            )],
        )
        .await
        .unwrap();
    chans
        .set_acls(
            44,
            true,
            vec![acl_for_group(
                "inner",
                ACLPermissions::Speak.into(),
                enumflags2::BitFlags::empty(),
                false,
            )],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    alice.query_acls(44).await;

    let Some(Message::ACL(resp)) = alice
        .recv_until(
            |m| matches!(m, Message::ACL(a) if a.channel_id == 44),
            Duration::from_secs(2),
        )
        .await
    else {
        panic!("Alice should receive an ACL response for channel 44");
    };

    let groups: Vec<_> = resp
        .acls
        .iter()
        .map(|acl| acl.group.as_deref().unwrap_or(""))
        .collect();
    let inherited: Vec<_> = resp
        .acls
        .iter()
        .map(|acl| acl.inherited.unwrap_or(true))
        .collect();

    assert_eq!(groups, vec!["outer", "middle", "inner"]);
    assert_eq!(inherited, vec![true, true, false]);
}

#[tokio::test]
async fn traverse_visibility_gate_off_keeps_existing_user_visibility() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 70).await;

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.move_to_channel(70).await;
    bob.recv_until(
        |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id) && us.channel_id == Some(70)),
        Duration::from_secs(2),
    )
    .await
    .expect("bob moves to secret channel");

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    assert!(
        alice
            .initial_user_states
            .iter()
            .any(|state| state.session == Some(bob.session_id) && state.channel_id == Some(70)),
        "gate-off clients should keep the existing unfiltered user list"
    );
}

#[tokio::test]
async fn traverse_visibility_hides_and_reveals_users_on_move() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 71).await;

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice
        .recv_until(
            |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id)),
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob in root");
    alice.drain_now().await;

    bob.move_to_channel(71).await;
    alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == bob.session_id),
            Duration::from_secs(2),
        )
        .await
        .expect("bob entering hidden channel is delivered as UserRemove");

    bob.move_to_channel(0).await;
    let rejoin = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.channel_id == Some(0)
                        && us.name.as_deref() == Some("bob")
                        && us.user_id == Some(2))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        rejoin.is_some(),
        "bob leaving the hidden channel should be delivered as a full UserState"
    );
}

#[tokio::test]
async fn traverse_visibility_filters_listener_add_and_remove() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 72).await;

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.send(
        UserState {
            session: Some(bob.server_session),
            listening_channel_add: vec![72],
            ..Default::default()
        }
        .into(),
    )
    .await;
    bob.recv_until(
        |m| {
            matches!(m, Message::UserState(us)
                if us.session == Some(bob.session_id)
                    && us.listening_channel_add.contains(&72))
        },
        Duration::from_secs(2),
    )
    .await
    .expect("bob sees his own listener add");

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob_state = alice
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(bob.session_id))
        .expect("bob is visible in root");
    assert!(
        !bob_state.listening_channel_add.contains(&72),
        "hidden listener channels must be omitted from full UserState"
    );

    alice.drain_now().await;
    bob.send(
        UserState {
            session: Some(bob.server_session),
            listening_channel_remove: vec![72],
            ..Default::default()
        }
        .into(),
    )
    .await;

    let invalid_remove = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.listening_channel_remove.contains(&72))
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(
        invalid_remove.is_none(),
        "clients must not receive listener removes for channels they never knew"
    );
}

#[tokio::test]
async fn traverse_visibility_delete_refresh_skips_unrelated_known_users() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(90, "Doomed".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice
        .recv_until(
            |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id)),
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob in root before unrelated delete");
    alice.drain_now().await;

    alice.remove_channel(90).await;
    alice
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == 90),
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees the deleted channel removed");

    let redundant_bob_refresh = alice
        .recv_until(
            |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id)),
            Duration::from_millis(300),
        )
        .await;
    assert!(
        redundant_bob_refresh.is_none(),
        "delete visibility refresh should not recheck unrelated known users"
    );
}

#[tokio::test]
async fn traverse_visibility_delete_refresh_removes_deleted_listener_channel() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(91, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(92, "Child".to_owned(), 0, 0, Some(91)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice
        .recv_until(
            |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id)),
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob before listener add");

    bob.send(
        UserState {
            session: Some(bob.server_session),
            listening_channel_add: vec![92],
            ..Default::default()
        }
        .into(),
    )
    .await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.listening_channel_add.contains(&92))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob listen to visible child");
    alice.drain_now().await;

    alice.remove_channel(91).await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.channel_id.is_none()
                        && us.listening_channel_remove == vec![92])
            },
            Duration::from_secs(2),
        )
        .await
        .expect("delete refresh should remove listener-only stale channels before channel removal");
    alice
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == 91),
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees parent removed after listener removal");
}

#[tokio::test]
async fn traverse_visibility_hidden_users_are_missing_from_targeted_surfaces() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 73).await;

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice
        .recv_until(
            |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id)),
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob before he enters the hidden channel");

    bob.move_to_channel(73).await;
    alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == bob.session_id),
            Duration::from_secs(2),
        )
        .await
        .expect("bob becomes hidden from alice");
    alice.drain_now().await;

    alice
        .send(
            UserStats {
                session: Some(bob.session_id),
                ..UserStats::default()
            }
            .into(),
        )
        .await;
    let hidden_stats = alice
        .recv_until(
            |m| matches!(m, Message::UserStats(us) if us.session == Some(bob.session_id)),
            Duration::from_millis(300),
        )
        .await;
    assert!(
        hidden_stats.is_none(),
        "UserStats should treat a hidden user as missing"
    );

    bob.send(
        TextMessage {
            session: vec![alice.session_id],
            message: "hidden text".to_owned(),
            ..TextMessage::default()
        }
        .into(),
    )
    .await;
    let hidden_text = alice
        .recv_until(
            |m| matches!(m, Message::TextMessage(tm) if tm.actor == Some(bob.session_id)),
            Duration::from_millis(300),
        )
        .await;
    assert!(
        hidden_text.is_none(),
        "direct text from a hidden sender should be dropped"
    );

    bob.send(
        PluginDataTransmission {
            receiver_sessions: vec![alice.session_id],
            data: Some(Bytes::from_static(b"hidden plugin")),
            data_id: Some("visibility-test".to_owned()),
            ..PluginDataTransmission::default()
        }
        .into(),
    )
    .await;
    let hidden_plugin = alice
        .recv_until(
            |m| {
                matches!(m, Message::PluginDataTransmission(p)
                    if p.sender_session == Some(bob.session_id))
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(
        hidden_plugin.is_none(),
        "plugin data from a hidden sender should be dropped"
    );

    bob.set_voice_target(VoiceTarget {
        id: Some(1),
        targets: vec![shitspeak_proto::mumble_proto::voice_target::Target {
            session: vec![alice.session_id],
            channel_id: None,
            group: None,
            links: Some(false),
            children: Some(false),
        }],
    })
    .await;
    bob.send_voice_tcp(1, 101, Bytes::from_static(b"hidden voice"))
        .await;
    let hidden_voice = alice.recv_voice_tcp(Duration::from_millis(300)).await;
    assert!(
        hidden_voice.is_none(),
        "voice target audio from a hidden sender should be dropped"
    );
}

#[tokio::test]
async fn traverse_visibility_initial_sync_filters_hidden_users() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 80).await;

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.move_to_channel(80).await;
    bob.recv_until(
        |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id) && us.channel_id == Some(80)),
        Duration::from_secs(2),
    )
    .await
    .expect("bob enters hidden channel");

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    assert!(
        !alice
            .initial_user_states
            .iter()
            .any(|state| state.session == Some(bob.session_id)),
        "initial sync should omit users whose current channel is not traversable"
    );
    assert!(
        alice
            .initial_channel_states
            .iter()
            .any(|channel| channel.channel_id == Some(80)),
        "hide_users_without_traverse alone should preserve channel visibility"
    );
}

#[tokio::test]
async fn traverse_visibility_honors_child_allow_over_inherited_deny() {
    let server = spawn_test_server(TestServerOpts {
        default_channel: 70,
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let channels = server.server.get_channels();
    channels
        .create_channel(Channel::new(70, "Default".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    channels
        .create_channel(Channel::new(71, "Sibling".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    channels
        .set_acls(
            0,
            true,
            vec![
                ACL {
                    user_id: None,
                    group: Some("all".to_owned()),
                    apply_here: true,
                    apply_subs: false,
                    allow: ACLPermissions::Traverse.into(),
                    deny: enumflags2::BitFlags::empty(),
                },
                ACL {
                    user_id: None,
                    group: Some("all".to_owned()),
                    apply_here: false,
                    apply_subs: true,
                    allow: enumflags2::BitFlags::empty(),
                    deny: ACLPermissions::Traverse.into(),
                },
            ],
        )
        .await
        .unwrap();
    for channel_id in [70, 71] {
        channels
            .set_acls(
                channel_id,
                true,
                vec![acl_for_group(
                    "all",
                    ACLPermissions::Traverse.into(),
                    enumflags2::BitFlags::empty(),
                    true,
                )],
            )
            .await
            .unwrap();
    }

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    assert!(
        alice
            .initial_channel_states
            .iter()
            .any(|channel| channel.channel_id == Some(70))
    );
    assert!(
        alice
            .initial_channel_states
            .iter()
            .any(|channel| channel.channel_id == Some(71)),
        "a sibling with the same local Traverse allow should be visible"
    );
    assert!(
        alice
            .initial_user_states
            .iter()
            .any(|state| { state.session == Some(bob.session_id) && state.channel_id == Some(70) }),
        "another user in the traversable default channel should be visible"
    );
}

#[tokio::test]
async fn traverse_visibility_filters_hidden_channel_requests() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    create_secret_channel(&server, 86).await;

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    alice.drain_now().await;

    alice
        .send(
            shitspeak_messages::messages::encoder::PermissionQuery {
                channel_id: Some(86),
                permissions: None,
                flush: None,
            }
            .into(),
        )
        .await;
    assert!(
        alice
            .recv_until(
                |m| matches!(m, Message::PermissionQuery(query) if query.channel_id == Some(86)),
                Duration::from_millis(300),
            )
            .await
            .is_none(),
        "hidden channel permission queries should not disclose channel state"
    );

    alice
        .send(
            shitspeak_messages::messages::encoder::RequestBlob {
                session_texture: Vec::new(),
                session_comment: Vec::new(),
                channel_description: vec![86],
            }
            .into(),
        )
        .await;
    assert!(
        alice
            .recv_until(
                |m| matches!(m, Message::ChannelState(state) if state.channel_id == Some(86)),
                Duration::from_millis(300),
            )
            .await
            .is_none(),
        "hidden channel descriptions should not disclose channel state"
    );
}

#[tokio::test]
async fn traverse_visibility_allows_viewers_with_traverse() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["secret".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 81).await;

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.move_to_channel(81).await;
    bob.recv_until(
        |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id) && us.channel_id == Some(81)),
        Duration::from_secs(2),
    )
    .await
    .expect("bob enters traversable secret channel");

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    assert!(
        alice
            .initial_user_states
            .iter()
            .any(|state| state.session == Some(bob.session_id) && state.channel_id == Some(81)),
        "clients with Traverse should still see users in restricted channels"
    );
}

#[tokio::test]
async fn traverse_visibility_reconciles_acl_changes() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_superuser("carol", None, Some(3), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(82, "Acl Flip".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(82).await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id) && us.channel_id == Some(82))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob before Traverse is denied");
    alice.drain_now().await;

    carol
        .set_acls(
            82,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: false,
                inherited: false,
                user_id: None,
                group: Some("all".to_owned()),
                grant: 0,
                deny: ACLPermissions::Traverse as u32,
            }],
            true,
        )
        .await;
    expect_channel_and_user_hidden(&alice, 82, bob.session_id).await;
    alice.drain_now().await;

    carol.set_acls(82, Vec::new(), true).await;
    expect_channel_and_user_revealed(&alice, 82, bob.session_id, "bob").await;
}

#[tokio::test]
async fn traverse_visibility_reconciles_links_across_visibility_boundary() {
    const SURVIVING_CHANNEL_ID: u32 = 81;
    const FLIPPING_CHANNEL_ID: u32 = 82;

    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_superuser("carol", None, Some(3), vec!["admin".into()]);

    let channels = server.server.get_channels();
    channels
        .create_channel(Channel::new(
            SURVIVING_CHANNEL_ID,
            "Visible Link Endpoint".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    channels
        .create_channel(Channel::new(
            FLIPPING_CHANNEL_ID,
            "Visibility Link Target".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    channels
        .add_link(SURVIVING_CHANNEL_ID, FLIPPING_CHANNEL_ID)
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");
    alice.drain_now().await;

    carol
        .set_acls(
            FLIPPING_CHANNEL_ID,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: false,
                inherited: false,
                user_id: None,
                group: Some("all".to_owned()),
                grant: 0,
                deny: ACLPermissions::Traverse as u32,
            }],
            true,
        )
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut hide_sequence = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = alice.recv(remaining).await else {
            break;
        };
        match message {
            Message::ChannelState(state)
                if state.channel_id == Some(SURVIVING_CHANNEL_ID)
                    && state.links_remove.contains(&FLIPPING_CHANNEL_ID) =>
            {
                hide_sequence.push("links-remove");
            }
            Message::ChannelRemove(remove) if remove.channel_id == FLIPPING_CHANNEL_ID => {
                hide_sequence.push("channel-remove");
                break;
            }
            _ => {}
        }
    }
    assert_eq!(
        hide_sequence,
        vec!["links-remove", "channel-remove"],
        "the surviving endpoint must be unlinked before the hidden channel is removed"
    );

    alice.drain_now().await;
    carol.set_acls(FLIPPING_CHANNEL_ID, Vec::new(), true).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut reveal_sequence = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = alice.recv(remaining).await else {
            break;
        };
        match message {
            Message::ChannelState(state)
                if state.channel_id == Some(FLIPPING_CHANNEL_ID) && state.name.is_some() =>
            {
                reveal_sequence.push("channel-state");
            }
            Message::ChannelState(state)
                if (state.channel_id == Some(SURVIVING_CHANNEL_ID)
                    && state.links_add.contains(&FLIPPING_CHANNEL_ID))
                    || (state.channel_id == Some(FLIPPING_CHANNEL_ID)
                        && state.links_add.contains(&SURVIVING_CHANNEL_ID)) =>
            {
                reveal_sequence.push("links-add");
                break;
            }
            _ => {}
        }
    }
    assert_eq!(
        reveal_sequence,
        vec!["channel-state", "links-add"],
        "the restored channel must be known before its link is reintroduced"
    );
}

#[tokio::test]
async fn live_acl_changes_do_not_hide_users_when_visibility_filtering_is_disabled() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_superuser("carol", None, Some(3), vec!["admin".into()]);

    server
        .server
        .get_channels()
        .create_channel(Channel::new(
            83,
            "Visible ACL Flip".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(83).await;
    alice
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(bob.session_id) && state.channel_id == Some(83))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob before the ACL update");
    alice.drain_now().await;

    carol
        .set_acls(
            83,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: false,
                inherited: false,
                user_id: None,
                group: Some("all".to_owned()),
                grant: 0,
                deny: ACLPermissions::Traverse as u32,
            }],
            true,
        )
        .await;

    assert!(
        alice
            .recv_until(
                |message| {
                    matches!(message, Message::UserRemove(remove)
                        if remove.session == bob.session_id)
                },
                Duration::from_millis(300),
            )
            .await
            .is_none(),
        "Traverse ACL changes must not hide users when filtering is disabled"
    );
}

#[tokio::test]
async fn traverse_visibility_retains_viewer_self_and_channel_after_losing_traverse() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_superuser("carol", None, Some(3), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(89, "Current".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    alice.move_to_channel(89).await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id) && us.channel_id == Some(89))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("alice enters her current channel");
    alice.drain_now().await;

    carol
        .set_acls(
            89,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: false,
                inherited: false,
                user_id: None,
                group: Some("all".to_owned()),
                grant: 0,
                deny: ACLPermissions::Traverse as u32,
            }],
            true,
        )
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut self_removed = false;
    let mut current_channel_removed = false;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = alice.recv(remaining).await else {
            break;
        };
        self_removed |=
            matches!(&message, Message::UserRemove(remove) if remove.session == alice.session_id);
        current_channel_removed |=
            matches!(&message, Message::ChannelRemove(remove) if remove.channel_id == 89);
    }

    assert!(
        !self_removed,
        "a viewer must not receive UserRemove for themselves after losing Traverse"
    );
    assert!(
        !current_channel_removed,
        "a viewer must retain their current channel after losing Traverse"
    );
}

#[tokio::test]
async fn traverse_visibility_reconciles_online_group_changes() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 87).await;

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.move_to_channel(87).await;
    bob.recv_until(
        |m| {
            matches!(m, Message::UserState(us)
                if us.session == Some(bob.session_id) && us.channel_id == Some(87))
        },
        Duration::from_secs(2),
    )
    .await
    .expect("bob enters secret channel");

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    assert!(
        !alice
            .initial_channel_states
            .iter()
            .any(|channel| channel.channel_id == Some(87)),
        "initial sync should omit channels Alice cannot traverse"
    );
    assert!(
        !alice
            .initial_user_states
            .iter()
            .any(|state| state.session == Some(bob.session_id)),
        "initial sync should omit users in channels Alice cannot traverse"
    );
    alice.drain_now().await;

    // Authentication sends ServerSync before the connection's visibility
    // baseline is installed in its projection shard. Wait for one projected
    // self update so the following group mutation is observed by a ready
    // projection rather than racing registration under suite load.
    alice.set_self_mute(true).await;
    alice
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(alice.session_id) && state.self_mute == Some(true))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("Alice's projection is ready");
    alice.drain_now().await;

    let live_alice = connected_client(&server, &alice).await;
    {
        let mut state = live_alice.write_global_state(server.server.get_clients());
        state.set_groups(["secret".to_owned()].into_iter().collect());
    }
    expect_channel_and_user_revealed(&alice, 87, bob.session_id, "bob").await;
    alice.drain_now().await;

    {
        let mut state = live_alice.write_global_state(server.server.get_clients());
        state.set_groups(Default::default());
    }
    expect_channel_and_user_hidden(&alice, 87, bob.session_id).await;
}

#[tokio::test]
async fn traverse_visibility_filters_channel_and_tree_text_from_hidden_sender() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 83).await;

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.move_to_channel(83).await;
    alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == bob.session_id),
            Duration::from_secs(2),
        )
        .await
        .expect("bob becomes hidden from alice");
    alice.drain_now().await;

    bob.send(
        TextMessage {
            channel_id: vec![0],
            message: "hidden channel text".to_owned(),
            ..TextMessage::default()
        }
        .into(),
    )
    .await;
    let hidden_channel_text = alice
        .recv_until(
            |m| matches!(m, Message::TextMessage(tm) if tm.actor == Some(bob.session_id)),
            Duration::from_millis(300),
        )
        .await;
    assert!(
        hidden_channel_text.is_none(),
        "channel text from a hidden sender should be dropped"
    );

    bob.send(
        TextMessage {
            tree_id: vec![0],
            message: "hidden tree text".to_owned(),
            ..TextMessage::default()
        }
        .into(),
    )
    .await;
    let hidden_tree_text = alice
        .recv_until(
            |m| matches!(m, Message::TextMessage(tm) if tm.actor == Some(bob.session_id)),
            Duration::from_millis(300),
        )
        .await;
    assert!(
        hidden_tree_text.is_none(),
        "tree text from a hidden sender should be dropped"
    );
}

#[tokio::test]
async fn traverse_visibility_allows_channel_and_listener_voice_for_visible_sender() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["secret".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["secret".into()]);

    create_secret_channel(&server, 86).await;

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.move_to_channel(86).await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id) && us.channel_id == Some(86))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("alice enters secret channel");
    bob.move_to_channel(86).await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id) && us.channel_id == Some(86))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob in traversable secret channel");
    alice.drain_now().await;

    bob.send_voice_tcp(0, 201, Bytes::from_static(b"visible channel voice"))
        .await;
    assert!(
        alice.recv_voice_tcp(Duration::from_secs(2)).await.is_some(),
        "normal channel voice should be delivered when the receiver can view the sender"
    );

    alice.move_to_channel(0).await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id) && us.channel_id == Some(0))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("alice returns to root");
    alice
        .send(
            UserState {
                session: Some(alice.server_session),
                listening_channel_add: vec![86],
                ..Default::default()
            }
            .into(),
        )
        .await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id)
                        && us.listening_channel_add.contains(&86))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("alice starts listening to the traversable secret channel");
    alice.drain_now().await;

    bob.send_voice_tcp(0, 202, Bytes::from_static(b"visible listener voice"))
        .await;
    assert!(
        alice.recv_voice_tcp(Duration::from_secs(2)).await.is_some(),
        "listener voice should be delivered when the listener can view the sender"
    );
}

#[tokio::test]
async fn traverse_visibility_scrubs_hidden_actor_from_projected_user_events() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server.authenticator.register_superuser(
        "carol",
        None,
        Some(3),
        vec!["admin".into(), "secret".into()],
    );

    create_secret_channel(&server, 84).await;
    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(85, "Public Move".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");
    alice
        .recv_until(
            |m| matches!(m, Message::UserState(us) if us.session == Some(bob.session_id)),
            Duration::from_secs(2),
        )
        .await
        .expect("alice sees bob before carol acts");

    carol.move_to_channel(84).await;
    alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == carol.session_id),
            Duration::from_secs(2),
        )
        .await
        .expect("carol is hidden from alice");
    alice.drain_now().await;

    carol.move_other(bob.session_id, 85).await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.channel_id == Some(85)
                        && us.actor.is_none())
            },
            Duration::from_secs(2),
        )
        .await
        .expect("hidden actor should be scrubbed from projected UserState");
    alice.drain_now().await;

    carol.kick(bob.session_id, "visibility actor").await;
    let removed = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserRemove(ur)
                    if ur.session == bob.session_id && ur.actor.is_none())
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        removed.is_some(),
        "hidden actor should be scrubbed from projected UserRemove"
    );
}

#[tokio::test]
async fn listen_add_requires_traverse_before_listen() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    create_secret_channel(&server, 73).await;

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    alice
        .send(
            UserState {
                session: Some(alice.server_session),
                listening_channel_add: vec![73],
                ..Default::default()
            }
            .into(),
        )
        .await;

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.channel_id == Some(73)
                        && pd.permission == Some(ACLPermissions::Traverse as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        denied.is_some(),
        "listen add should report missing Traverse before checking Listen"
    );
}

fn acl_for_group(
    group: &str,
    allow: enumflags2::BitFlags<ACLPermissions>,
    deny: enumflags2::BitFlags<ACLPermissions>,
    apply_subs: bool,
) -> ACL {
    ACL {
        user_id: None,
        group: Some(group.to_owned()),
        apply_here: true,
        apply_subs,
        allow,
        deny,
    }
}

async fn expect_channel_and_user_hidden(client: &TestClient, channel_id: u32, session_id: u32) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut channel_removed = false;
    let mut user_removed = false;
    let mut sequence = Vec::new();

    while tokio::time::Instant::now() < deadline && !(channel_removed && user_removed) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = client.recv(remaining).await else {
            break;
        };
        if matches!(&message, Message::ChannelRemove(cr) if cr.channel_id == channel_id) {
            channel_removed = true;
            sequence.push("channel-remove");
        }
        if matches!(&message, Message::UserRemove(ur) if ur.session == session_id) {
            user_removed = true;
            sequence.push("user-remove");
        }
    }

    assert!(
        channel_removed,
        "channel {channel_id} should be removed when it is no longer traversable"
    );
    assert!(
        user_removed,
        "user {session_id} should be removed when their channel is no longer traversable"
    );
    assert_eq!(
        sequence,
        vec!["user-remove", "channel-remove"],
        "user/listener removals must precede channel removal"
    );
}

async fn expect_channel_and_user_revealed(
    client: &TestClient,
    channel_id: u32,
    session_id: u32,
    user_name: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut channel_revealed = false;
    let mut user_revealed = false;
    let mut sequence = Vec::new();

    while tokio::time::Instant::now() < deadline && !(channel_revealed && user_revealed) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = client.recv(remaining).await else {
            break;
        };
        if matches!(&message, Message::ChannelState(cs)
            if cs.channel_id == Some(channel_id) && cs.name.is_some())
        {
            channel_revealed = true;
            sequence.push("channel-state");
        }
        if matches!(&message, Message::UserState(us)
            if us.session == Some(session_id)
                && us.channel_id == Some(channel_id)
                && us.name.as_deref() == Some(user_name))
        {
            user_revealed = true;
            sequence.push("user-state");
        }
    }

    assert!(
        channel_revealed,
        "channel {channel_id} should be republished when it becomes traversable"
    );
    assert!(
        user_revealed,
        "user {session_id} should be republished when their channel becomes traversable"
    );
    assert_eq!(
        sequence,
        vec!["channel-state", "user-state"],
        "channel must be republished before user state"
    );
}

async fn create_secret_channel(
    server: &crate::integration_tests::harness::TestServer,
    channel_id: u32,
) {
    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(
            channel_id,
            format!("Secret {channel_id}"),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    chans
        .set_acls(
            channel_id,
            true,
            vec![acl_for_group(
                "!secret",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Traverse.into(),
                true,
            )],
        )
        .await
        .unwrap();
}

fn empty_channel_patch() -> ChannelPatch {
    ChannelPatch {
        name: None,
        position: None,
        max_users: None,
        description_hash: None,
        parent_id: None,
    }
}

async fn connected_client(
    server: &crate::integration_tests::harness::TestServer,
    client: &TestClient,
) -> std::sync::Arc<Box<crate::client::Client>> {
    server
        .server
        .get_clients()
        .get_client(client.server_session)
        .await
        .expect("connected client")
}

async fn cached_permissions(
    server: &crate::integration_tests::harness::TestServer,
    client: &TestClient,
    channel_id: u32,
) -> enumflags2::BitFlags<ACLPermissions> {
    let client = connected_client(server, client).await;
    crate::client::acl::compute_permissions_for_client(&server.server, &client, channel_id).await
}

async fn send_token_update(client: &TestClient, tokens: Vec<&str>) {
    let message: Message = Authenticate {
        username: None,
        password: None,
        tokens: tokens.into_iter().map(str::to_owned).collect(),
        celt_versions: Vec::new(),
        opus: Some(true),
        client_type: ClientType::Regular,
    }
    .into();
    client.send(message).await;
}

#[tokio::test]
async fn acl_cache_home_move_only_invalidates_home_dependent_entries() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let channels = server.server.get_channels();
    channels
        .create_channel(Channel::new(200, "Static ACL".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    channels
        .create_channel(Channel::new(201, "Home ACL".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    channels
        .create_channel(Channel::new(202, "Destination".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    channels
        .set_acls(
            200,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();
    channels
        .set_acls(
            201,
            true,
            vec![acl_for_group(
                "in",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let client = connected_client(&server, &bob).await;
    let _ = cached_permissions(&server, &bob, 200).await;
    let _ = cached_permissions(&server, &bob, 201).await;

    let server_id = client.server_id();
    let static_channel_generation = channels.channel_acl_generation_for_channel(&server_id, 200);
    let home_channel_generation = channels.channel_acl_generation_for_channel(&server_id, 201);
    let (subject_generation, old_home_generation) = client.get_acl_cache_generations();

    assert!(
        client
            .get_cached_acl_permissions(
                200,
                static_channel_generation,
                subject_generation,
                old_home_generation,
                false,
            )
            .is_some()
    );
    assert!(
        client
            .get_cached_acl_permissions(
                201,
                home_channel_generation,
                subject_generation,
                old_home_generation,
                false,
            )
            .is_some()
    );

    assert!(
        client
            .write_global_state_direct()
            .set_current_channel_id(202)
    );
    let (same_subject_generation, new_home_generation) = client.get_acl_cache_generations();
    assert_eq!(same_subject_generation, subject_generation);
    assert_ne!(new_home_generation, old_home_generation);

    assert!(
        client
            .get_cached_acl_permissions(
                200,
                static_channel_generation,
                same_subject_generation,
                new_home_generation,
                false,
            )
            .is_some()
    );
    assert!(
        client
            .get_cached_acl_permissions(
                201,
                home_channel_generation,
                same_subject_generation,
                new_home_generation,
                false,
            )
            .is_none()
    );

    client
        .write_global_state_direct()
        .set_groups(std::iter::once("member".to_owned()).collect());
    let (new_subject_generation, current_home_generation) = client.get_acl_cache_generations();
    assert_ne!(new_subject_generation, same_subject_generation);
    assert!(
        client
            .get_cached_acl_permissions(
                200,
                static_channel_generation,
                new_subject_generation,
                current_home_generation,
                false,
            )
            .is_none()
    );
}

#[tokio::test]
async fn acl_cache_parent_acl_change_updates_descendant_permissions() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(50, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(51, "Child".to_owned(), 0, 0, Some(50)))
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let initial = cached_permissions(&server, &bob, 51).await;
    assert!(initial.contains(ACLPermissions::Enter));

    chans
        .set_acls(
            50,
            true,
            vec![acl_for_group(
                "all",
                ACLPermissions::Enter.into(),
                ACLPermissions::Enter.into(),
                true,
            )],
        )
        .await
        .unwrap();

    let after = cached_permissions(&server, &bob, 51).await;
    assert!(!after.contains(ACLPermissions::Enter));
}

#[tokio::test]
async fn acl_cache_parent_acl_change_does_not_invalidate_unrelated_channel_cache() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(
            54,
            "Affected Parent".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(
            55,
            "Affected Child".to_owned(),
            0,
            0,
            Some(54),
        ))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(56, "Unrelated".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let bob_client = connected_client(&server, &bob).await;
    let cache_generation_before = server
        .server
        .get_channels()
        .channel_acl_generation_for_channel(&bob_client.server_id(), 56);
    let unrelated = cached_permissions(&server, &bob, 56).await;
    assert!(unrelated.contains(ACLPermissions::Enter));

    chans
        .set_acls(
            54,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                true,
            )],
        )
        .await
        .unwrap();

    let cache_generation_after = server
        .server
        .get_channels()
        .channel_acl_generation_for_channel(&bob_client.server_id(), 56);
    assert_eq!(
        cache_generation_before, cache_generation_after,
        "Changing a parent ACL should not bump cache generation for unrelated channels"
    );
    let unrelated_after = cached_permissions(&server, &bob, 56).await;
    assert_eq!(unrelated, unrelated_after);
}

#[tokio::test]
async fn explicit_enter_deny_can_override_write_permission() {
    let server = spawn_test_server(TestServerOpts {
        explicit_enter_deny_overrides_write: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(52, "Writable".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            52,
            true,
            vec![acl_for_group(
                "all",
                ACLPermissions::Write.into(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let permissions = cached_permissions(&server, &bob, 52).await;
    assert!(permissions.contains(ACLPermissions::Write));
    assert!(!permissions.contains(ACLPermissions::Enter));
}

#[tokio::test]
async fn acl_cache_inherit_toggle_updates_child_permissions() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(52, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(53, "Child".to_owned(), 0, 0, Some(52)))
        .await
        .unwrap();
    chans
        .set_acls(
            52,
            true,
            vec![acl_for_group(
                "all",
                ACLPermissions::Enter.into(),
                ACLPermissions::Enter.into(),
                true,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let denied = cached_permissions(&server, &bob, 53).await;
    assert!(!denied.contains(ACLPermissions::Enter));

    chans
        .set_acls(
            53,
            false,
            vec![acl_for_group(
                "all",
                ACLPermissions::Enter.into(),
                enumflags2::BitFlags::empty(),
                false,
            )],
        )
        .await
        .unwrap();

    let after = cached_permissions(&server, &bob, 53).await;
    assert!(after.contains(ACLPermissions::Enter));
}

#[tokio::test]
async fn acl_child_allow_overrides_parent_deny() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(60, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(61, "Child".to_owned(), 0, 0, Some(60)))
        .await
        .unwrap();

    chans
        .set_acls(
            60,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::TextMessage.into(),
                true,
            )],
        )
        .await
        .unwrap();
    chans
        .set_acls(
            61,
            true,
            vec![acl_for_group(
                "all",
                ACLPermissions::TextMessage.into(),
                enumflags2::BitFlags::empty(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let parent = cached_permissions(&server, &bob, 60).await;
    assert!(!parent.contains(ACLPermissions::TextMessage));

    let child = cached_permissions(&server, &bob, 61).await;
    assert!(
        child.contains(ACLPermissions::TextMessage),
        "Child ACL allow should override inherited parent deny"
    );
}

#[tokio::test]
async fn acl_target_inherit_false_drops_parent_denies() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(63, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(64, "Child".to_owned(), 0, 0, Some(63)))
        .await
        .unwrap();

    chans
        .set_acls(
            63,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::TextMessage.into(),
                true,
            )],
        )
        .await
        .unwrap();
    chans.set_acls(64, false, Vec::new()).await.unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let child = cached_permissions(&server, &bob, 64).await;
    assert!(
        child.contains(ACLPermissions::TextMessage),
        "Target inherit_acl=false should drop inherited parent deny rules"
    );
}

#[tokio::test]
async fn permission_query_reports_evaluated_bits() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(62, "NoText".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            62,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::TextMessage.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.send(
        shitspeak_messages::messages::encoder::PermissionQuery {
            channel_id: Some(62),
            permissions: None,
            flush: None,
        }
        .into(),
    )
    .await;

    let msg = bob
        .recv_until(
            |m| matches!(m, Message::PermissionQuery(pq) if pq.channel_id == Some(62)),
            Duration::from_secs(2),
        )
        .await;

    let Some(Message::PermissionQuery(reply)) = msg else {
        panic!("Bob should receive PermissionQuery response");
    };
    let permissions = reply.permissions.expect("permissions");
    assert_ne!(permissions & CLIENT_PERMISSION_CACHE_BIT, 0);
    assert_eq!(permissions & ACLPermissions::TextMessage as u32, 0);
}

#[tokio::test]
async fn permission_query_marks_empty_permissions_cached() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    create_secret_channel(&server, 63).await;

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.send(
        shitspeak_messages::messages::encoder::PermissionQuery {
            channel_id: Some(63),
            permissions: None,
            flush: None,
        }
        .into(),
    )
    .await;

    let msg = bob
        .recv_until(
            |m| matches!(m, Message::PermissionQuery(pq) if pq.channel_id == Some(63)),
            Duration::from_secs(2),
        )
        .await;

    let Some(Message::PermissionQuery(reply)) = msg else {
        panic!("Bob should receive PermissionQuery response");
    };
    assert_eq!(reply.permissions, Some(CLIENT_PERMISSION_CACHE_BIT));
}

#[tokio::test]
async fn user_without_user_id_matches_all_but_not_auth_group() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, None, vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(72, "Guest".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            72,
            true,
            vec![
                acl_for_group(
                    "all",
                    ACLPermissions::TempChannel.into(),
                    enumflags2::BitFlags::empty(),
                    false,
                ),
                acl_for_group(
                    "auth",
                    ACLPermissions::MakeChannel.into(),
                    enumflags2::BitFlags::empty(),
                    false,
                ),
            ],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let permissions = cached_permissions(&server, &bob, 72).await;
    assert!(permissions.contains(ACLPermissions::TempChannel));
    assert!(!permissions.contains(ACLPermissions::MakeChannel));
}

#[tokio::test]
async fn entering_channel_sends_permission_query_for_channel_and_parent() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(65, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(66, "Child".to_owned(), 0, 0, Some(65)))
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(66).await;

    let child = bob
        .recv_until(
            |m| matches!(m, Message::PermissionQuery(pq) if pq.channel_id == Some(66)),
            Duration::from_secs(2),
        )
        .await;
    let parent = bob
        .recv_until(
            |m| matches!(m, Message::PermissionQuery(pq) if pq.channel_id == Some(65)),
            Duration::from_secs(2),
        )
        .await;

    let Some(Message::PermissionQuery(child)) = child else {
        panic!("Bob should receive PermissionQuery for entered channel");
    };
    let Some(Message::PermissionQuery(parent)) = parent else {
        panic!("Bob should receive PermissionQuery for parent channel");
    };
    assert!(child.permissions.is_some());
    assert!(parent.permissions.is_some());
}

#[tokio::test]
async fn in_group_speak_allow_clears_suppress_after_entering_channel() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .set_acls(
            0,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Speak.into(),
                true,
            )],
        )
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(74, "Stage".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            74,
            true,
            vec![acl_for_group(
                "in",
                ACLPermissions::Speak.into(),
                enumflags2::BitFlags::empty(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    assert!(
        bob.initial_user_states
            .iter()
            .any(|state| { state.session == Some(bob.session_id) && state.suppress == Some(true) }),
        "Root Speak deny should suppress Bob before the move"
    );

    bob.move_to_channel(74).await;

    let moved = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.channel_id == Some(74)
                        && us.suppress == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        moved.is_some(),
        "in +Speak should clear suppression after Bob enters the channel"
    );
}

#[tokio::test]
async fn cached_login_into_in_group_speak_channel_starts_unsuppressed() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .set_acls(
            0,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Speak.into(),
                true,
            )],
        )
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(75, "Fleet 04".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(
            76,
            "Fleet 04 Ready".to_owned(),
            0,
            0,
            Some(75),
        ))
        .await
        .unwrap();
    chans
        .set_acls(
            76,
            true,
            vec![acl_for_group(
                "in",
                ACLPermissions::Speak.into(),
                enumflags2::BitFlags::empty(),
                false,
            )],
        )
        .await
        .unwrap();
    server
        .server
        .get_user_channel_cache()
        .remember_last_channel("2", 76)
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let self_state = bob
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(bob.session_id))
        .expect("Bob self state");

    assert_eq!(self_state.channel_id, Some(76));
    assert_ne!(
        self_state.suppress,
        Some(true),
        "in +Speak should keep Bob unsuppressed when login restores him into the channel"
    );
}

#[tokio::test]
async fn cached_login_without_traverse_falls_back_to_default_channel() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let channels = server.server.get_channels();
    channels
        .create_channel(Channel::new(78, "Cached hidden".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    channels
        .set_acls(
            78,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Traverse.into(),
                false,
            )],
        )
        .await
        .unwrap();
    server
        .server
        .get_user_channel_cache()
        .remember_last_channel(&test_user_channel_cache_key(2), 78)
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let self_state = bob
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(bob.session_id))
        .expect("Bob self state");

    assert_eq!(
        self_state.channel_id,
        Some(0),
        "a cached channel without Traverse must not be restored"
    );
    assert_eq!(
        server
            .server
            .get_user_channel_cache()
            .get(&test_user_channel_cache_key(2))
            .await
            .and_then(|channels| channels.last_channel_id),
        Some(0),
        "the fallback channel should replace the unusable cache entry"
    );
}

#[tokio::test]
async fn cached_listener_without_listen_permission_is_not_restored() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let channels = server.server.get_channels();
    channels
        .create_channel(Channel::new(
            79,
            "Cached listener".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    channels
        .set_acls(
            79,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Listen.into(),
                false,
            )],
        )
        .await
        .unwrap();
    server
        .server
        .get_user_channel_cache()
        .remember_listening_channels(&test_user_channel_cache_key(2), [79])
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let self_state = bob
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(bob.session_id))
        .expect("Bob self state");
    assert!(
        !self_state.listening_channel_add.contains(&79),
        "a cached listener without ACL Listen permission must not be restored"
    );
    // The denied listener is pruned from the persisted cache asynchronously,
    // *after* the server sends the login burst (see authenticate.rs
    // staged_channel_cache_write). ServerSync arrives with the burst, so
    // connect_and_authenticate can return before the prune lands. Poll until
    // it does instead of racing the single write.
    let pruned = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let cached = server
                .server
                .get_user_channel_cache()
                .get(&test_user_channel_cache_key(2))
                .await;
            if cached.is_none_or(|channels| channels.listening_channel_ids.is_empty()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(
        pruned.is_ok(),
        "the denied listener must be removed from the persisted cache"
    );
}

#[tokio::test]
async fn acl_cache_does_not_cross_reused_local_session_ids() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .set_acls(
            0,
            true,
            vec![
                acl_for_group(
                    "all",
                    enumflags2::BitFlags::empty(),
                    ACLPermissions::Speak.into(),
                    true,
                ),
                ACL {
                    user_id: Some(2),
                    group: None,
                    apply_here: true,
                    apply_subs: true,
                    allow: ACLPermissions::Speak.into(),
                    deny: enumflags2::BitFlags::empty(),
                },
            ],
        )
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(77, "Fleet 04".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    server
        .server
        .get_user_channel_cache()
        .remember_last_channel("1", 77)
        .await
        .unwrap();
    server
        .server
        .get_user_channel_cache()
        .remember_last_channel("2", 77)
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let alice_perms = cached_permissions(&server, &alice, 77).await;
    assert!(
        !alice_perms.contains(ACLPermissions::Speak),
        "Alice should prime a no-Speak cache entry for channel 77"
    );
    let alice_session_id = alice.session_id;
    drop(alice);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let self_state = bob
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(bob.session_id))
        .expect("Bob self state");

    assert_eq!(
        bob.session_id, alice_session_id,
        "the test needs local session id reuse to reproduce the stale-cache shape"
    );
    assert_eq!(self_state.channel_id, Some(77));
    assert_ne!(
        self_state.suppress,
        Some(true),
        "Bob must not inherit Alice's cached no-Speak permission after session id reuse"
    );
}

#[tokio::test]
async fn acl_cache_acl_update_sends_channel_scoped_permission_refresh_to_all_clients() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(67, "Shared".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice.drain_now().await;
    bob.drain_now().await;

    chans
        .set_acls(
            67,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::TextMessage.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let alice_refresh = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(pq)
                    if pq.channel_id == Some(67)
                        && pq.permissions.is_some()
                        && pq.flush == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    let bob_refresh = bob
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(pq)
                    if pq.channel_id == Some(67)
                        && pq.permissions.is_some()
                        && pq.flush == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;

    let Some(Message::PermissionQuery(alice_refresh)) = alice_refresh else {
        panic!("Alice should receive channel-scoped ACL cache refresh");
    };
    let Some(Message::PermissionQuery(bob_refresh)) = bob_refresh else {
        panic!("Bob should receive channel-scoped ACL cache refresh");
    };
    assert_eq!(alice_refresh.flush, Some(false));
    assert_eq!(bob_refresh.flush, Some(false));

    let alice_flush = alice
        .recv_until(
            |m| matches!(m, Message::PermissionQuery(pq) if pq.flush == Some(true)),
            Duration::from_millis(250),
        )
        .await;
    let bob_flush = bob
        .recv_until(
            |m| matches!(m, Message::PermissionQuery(pq) if pq.flush == Some(true)),
            Duration::from_millis(250),
        )
        .await;
    assert!(
        alice_flush.is_none() && bob_flush.is_none(),
        "ACL updates should not send global permission cache flushes"
    );
}

#[tokio::test]
async fn identical_acl_save_preserves_version_and_emits_no_permission_refresh() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(68, "Stable".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice.drain_now().await;
    bob.drain_now().await;

    let acls = vec![ChanAcl {
        apply_here: true,
        apply_subs: false,
        inherited: false,
        user_id: None,
        group: Some("all".to_owned()),
        grant: 0,
        deny: ACLPermissions::TextMessage as u32,
    }];
    alice.set_acls(68, acls.clone(), true).await;
    bob.recv_until(
        |m| {
            matches!(m, Message::PermissionQuery(pq)
                if pq.channel_id == Some(68)
                    && pq.permissions.is_some()
                    && pq.flush == Some(false))
        },
        Duration::from_secs(2),
    )
    .await
    .expect("the first ACL save should refresh Bob's channel permissions");
    alice.drain_now().await;
    bob.drain_now().await;

    let bob_client = connected_client(&server, &bob).await;
    let server_id = bob_client.server_id();
    let version_before = chans.current_version_in_server(&server_id);
    let generation_before = chans.channel_acl_generation_for_channel(&server_id, 68);

    alice.set_acls(68, acls, true).await;

    let duplicate_refresh = bob
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(pq) if pq.channel_id == Some(68))
                    || matches!(m, Message::ChannelState(cs) if cs.channel_id == Some(68))
                    || matches!(m, Message::ChannelRemove(remove) if remove.channel_id == 68)
            },
            Duration::from_millis(300),
        )
        .await;
    let editor_duplicate_refresh = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(pq) if pq.channel_id == Some(68))
                    || matches!(m, Message::ChannelState(cs) if cs.channel_id == Some(68))
                    || matches!(m, Message::ChannelRemove(remove) if remove.channel_id == 68)
            },
            Duration::from_millis(100),
        )
        .await;
    assert!(
        duplicate_refresh.is_none() && editor_duplicate_refresh.is_none(),
        "an identical ACL save should not fan out another permission refresh"
    );
    assert_eq!(
        chans.current_version_in_server(&server_id),
        version_before,
        "an identical ACL save should not append another channel operation"
    );
    assert_eq!(
        chans.channel_acl_generation_for_channel(&server_id, 68),
        generation_before,
        "an identical ACL save should not invalidate the channel ACL cache"
    );
}

#[tokio::test]
async fn explicit_user_non_traverse_acl_delta_refreshes_only_target_user() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_superuser("carol", None, Some(3), vec!["admin".into()]);
    server
        .authenticator
        .register_user("dave", None, Some(4), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(90, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(91, "Child".to_owned(), 0, 0, Some(90)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let dave = TestClient::connect_and_authenticate(&server, "dave", None)
        .await
        .expect("dave");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(91).await;
    for viewer in [&alice, &dave] {
        viewer
            .recv_until(
                |m| {
                    matches!(m, Message::UserState(us)
                        if us.session == Some(bob.session_id)
                            && us.channel_id == Some(91))
                },
                Duration::from_secs(2),
            )
            .await
            .expect("both viewers should see Bob before the ACL edit");
    }
    alice.drain_now().await;
    dave.drain_now().await;
    bob.drain_now().await;
    carol.drain_now().await;

    carol
        .set_acls(
            90,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: true,
                inherited: false,
                user_id: Some(1),
                group: None,
                grant: 0,
                deny: ACLPermissions::TextMessage as u32,
            }],
            true,
        )
        .await;

    let mut parent_refreshed = false;
    let mut child_refreshed = false;
    let mut visibility_churn = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline && !(parent_refreshed && child_refreshed) {
        let Some(message) = alice.recv(Duration::from_millis(100)).await else {
            continue;
        };
        match message {
            Message::PermissionQuery(query) if query.permissions.is_some() => {
                parent_refreshed |= query.channel_id == Some(90);
                child_refreshed |= query.channel_id == Some(91);
            }
            Message::ChannelRemove(remove) => {
                visibility_churn |= matches!(remove.channel_id, 90 | 91);
            }
            Message::UserRemove(remove) => {
                visibility_churn |= remove.session == bob.session_id;
            }
            Message::UserState(state) => {
                visibility_churn |= state.session == Some(bob.session_id);
            }
            _ => {}
        }
    }
    assert!(
        parent_refreshed && child_refreshed,
        "Alice's changed TextMessage permission should refresh on the parent and inherited child"
    );
    let delayed_visibility_churn = alice
        .recv_until(
            |m| {
                matches!(m, Message::ChannelRemove(remove)
                    if matches!(remove.channel_id, 90 | 91))
                    || matches!(m, Message::UserRemove(remove)
                        if remove.session == bob.session_id)
                    || matches!(m, Message::UserState(state)
                        if state.session == Some(bob.session_id))
            },
            Duration::from_millis(200),
        )
        .await;
    assert!(
        !visibility_churn && delayed_visibility_churn.is_none(),
        "a non-Traverse ACL delta should not reconcile channel or user visibility"
    );

    let unaffected_refresh = dave
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(query)
                    if matches!(query.channel_id, Some(90 | 91)))
                    || matches!(m, Message::ChannelRemove(remove)
                        if matches!(remove.channel_id, 90 | 91))
                    || matches!(m, Message::UserRemove(remove)
                        if remove.session == bob.session_id)
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(
        unaffected_refresh.is_none(),
        "Dave's effective permissions and visibility did not change"
    );
}

#[tokio::test]
async fn explicit_user_traverse_delta_reconciles_only_target_across_subtree() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_superuser("carol", None, Some(3), vec!["admin".into()]);
    server
        .authenticator
        .register_user("dave", None, Some(4), vec![]);

    let chans = server.server.get_channels();
    for (channel_id, parent_id) in [
        (100, 0),
        (101, 100),
        (102, 100),
        (103, 101),
        (104, 101),
        (105, 102),
        (106, 105),
        (107, 0),
    ] {
        chans
            .create_channel(Channel::new(
                channel_id,
                format!("Channel {channel_id}"),
                0,
                0,
                Some(parent_id),
            ))
            .await
            .unwrap();
    }

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let dave = TestClient::connect_and_authenticate(&server, "dave", None)
        .await
        .expect("dave");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(106).await;
    for viewer in [&alice, &dave] {
        viewer
            .recv_until(
                |m| {
                    matches!(m, Message::UserState(us)
                        if us.session == Some(bob.session_id)
                            && us.channel_id == Some(106))
                },
                Duration::from_secs(2),
            )
            .await
            .expect("both viewers should see Bob before the ACL edit");
    }
    alice.drain_now().await;
    dave.drain_now().await;
    bob.drain_now().await;
    carol.drain_now().await;

    carol
        .set_acls(
            100,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: true,
                inherited: false,
                user_id: Some(1),
                group: None,
                grant: 0,
                deny: ACLPermissions::Traverse as u32,
            }],
            true,
        )
        .await;

    let mut removed_channels = [false; 7];
    let mut bob_removed = false;
    let mut unrelated_removed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline
        && (!bob_removed || removed_channels.iter().any(|removed| !removed))
    {
        let Some(message) = alice.recv(Duration::from_millis(100)).await else {
            continue;
        };
        match message {
            Message::UserRemove(remove) => {
                bob_removed |= remove.session == bob.session_id;
            }
            Message::ChannelRemove(remove) if (100..=106).contains(&remove.channel_id) => {
                removed_channels[(remove.channel_id - 100) as usize] = true;
            }
            Message::ChannelRemove(remove) => {
                unrelated_removed |= remove.channel_id == 107;
            }
            _ => {}
        }
    }
    assert!(
        bob_removed,
        "Alice should stop seeing Bob in the hidden subtree"
    );
    assert!(
        removed_channels.iter().all(|removed| *removed),
        "Alice should receive removals for the entire affected subtree"
    );
    assert!(
        !unrelated_removed,
        "the unrelated root branch should remain visible to Alice"
    );

    let unaffected_refresh = dave
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(query)
                    if query.channel_id.is_some_and(|id| (100..=106).contains(&id)))
                    || matches!(m, Message::ChannelRemove(remove)
                        if (100..=107).contains(&remove.channel_id))
                    || matches!(m, Message::UserRemove(remove)
                        if remove.session == bob.session_id)
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(
        unaffected_refresh.is_none(),
        "Dave's effective permissions and visibility did not change"
    );
}

#[tokio::test]
async fn inherited_traverse_delta_closes_visibility_across_acl_barrier() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_superuser("carol", None, Some(3), vec!["admin".into()]);

    let channels = server.server.get_channels();
    channels
        .create_channel(Channel::new(110, "Edited".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    channels
        .create_channel(Channel::new(111, "Inheriting".to_owned(), 0, 0, Some(110)))
        .await
        .unwrap();
    channels
        .create_channel(Channel::new(112, "Barrier".to_owned(), 0, 0, Some(111)))
        .await
        .unwrap();
    channels.set_acls(112, false, Vec::new()).await.unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(112).await;
    alice
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(bob.session_id)
                        && state.channel_id == Some(112))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("Alice should initially see Bob beyond the ACL barrier");
    alice.drain_now().await;
    bob.drain_now().await;
    carol.drain_now().await;

    carol
        .set_acls(
            110,
            vec![ChanAcl {
                apply_here: false,
                apply_subs: true,
                inherited: false,
                user_id: Some(1),
                group: None,
                grant: 0,
                deny: ACLPermissions::Traverse as u32,
            }],
            true,
        )
        .await;

    let mut removed_inheriting = false;
    let mut removed_barrier = false;
    let mut removed_bob = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline
        && !(removed_inheriting && removed_barrier && removed_bob)
    {
        let Some(message) = alice.recv(Duration::from_millis(100)).await else {
            continue;
        };
        match message {
            Message::ChannelRemove(remove) => {
                removed_inheriting |= remove.channel_id == 111;
                removed_barrier |= remove.channel_id == 112;
            }
            Message::UserRemove(remove) => removed_bob |= remove.session == bob.session_id,
            _ => {}
        }
    }

    assert!(
        removed_inheriting,
        "the inheriting channel should be hidden"
    );
    assert!(
        removed_barrier,
        "a structurally unreachable ACL barrier must also be removed"
    );
    assert!(
        removed_bob,
        "users below the structurally hidden ancestor must be removed"
    );
}

#[tokio::test]
async fn acl_update_reevaluates_speak_suppress_when_enabled() {
    let server = spawn_test_server(TestServerOpts {
        reevaluate_speak_on_acl_change: true,
        ..TestServerOpts::default()
    })
    .await;
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
    alice.drain_now().await;
    bob.drain_now().await;

    alice
        .set_acls(
            0,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: true,
                inherited: false,
                user_id: None,
                group: Some("all".to_owned()),
                grant: 0,
                deny: ACLPermissions::Speak as u32,
            }],
            true,
        )
        .await;

    let suppressed = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.suppress == Some(true))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        suppressed.is_some(),
        "Bob should be suppressed when an ACL edit removes Speak and reevaluation is enabled"
    );
}

#[tokio::test]
async fn acl_update_does_not_reevaluate_speak_suppress_by_default() {
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
    alice.drain_now().await;
    bob.drain_now().await;

    alice
        .set_acls(
            0,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: true,
                inherited: false,
                user_id: None,
                group: Some("all".to_owned()),
                grant: 0,
                deny: ACLPermissions::Speak as u32,
            }],
            true,
        )
        .await;

    let suppressed = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id)
                        && us.suppress == Some(true))
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(
        suppressed.is_none(),
        "Bob should not receive suppress reevaluation from ACL edits by default"
    );
}

#[tokio::test]
async fn acl_cache_per_user_purge_sends_scoped_permission_refresh_only_to_that_user() {
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
    alice.drain_now().await;
    bob.drain_now().await;

    send_token_update(&bob, vec!["door"]).await;

    let bob_refresh = bob
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(pq)
                    if pq.channel_id.is_some()
                        && pq.permissions.is_some()
                        && pq.flush == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        bob_refresh.is_some(),
        "Bob should receive his per-user scoped ACL cache refresh"
    );

    let alice_refresh = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(pq)
                    if pq.channel_id.is_some()
                        && pq.permissions.is_some()
                        && pq.flush == Some(false))
            },
            Duration::from_millis(250),
        )
        .await;
    assert!(
        alice_refresh.is_none(),
        "Alice should not receive Bob's per-user scoped ACL cache refresh"
    );
}

#[tokio::test]
async fn channel_state_initial_sync_includes_permission_info_when_enabled() {
    let server = spawn_test_server(TestServerOpts {
        send_permission_info: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    server
        .server
        .get_channels()
        .create_channel(Channel::new(68, "Private".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    server
        .server
        .get_channels()
        .set_acls(
            68,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let private = channel_permission_info(&bob, 68)
        .await
        .expect("private permission info");
    assert_eq!(private.is_enter_restricted, Some(true));
    assert_eq!(private.can_enter, Some(false));
}

#[tokio::test]
async fn initial_permission_info_is_embedded_without_a_deferred_duplicate_sweep() {
    let server = spawn_test_server(TestServerOpts {
        auth_finalization_concurrency: 1,
        send_permission_info: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    // A non-trivial tree exercises the ACL work that used to run again in a
    // detached full-channel refresh after the initial snapshot.
    let last_channel_id = 96;
    for channel_id in 1..=last_channel_id {
        server
            .server
            .get_channels()
            .create_channel(Channel::new(
                channel_id,
                format!("channel-{channel_id}"),
                channel_id as i32,
                0,
                Some(0),
            ))
            .await
            .unwrap();
    }

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let initial_matches: Vec<_> = bob
        .initial_channel_states
        .iter()
        .filter(|state| state.channel_id == Some(last_channel_id))
        .collect();
    assert_eq!(
        initial_matches.len(),
        1,
        "the final channel should occur exactly once before ServerSync"
    );
    let initial = initial_matches[0];
    assert_eq!(initial.name.as_deref(), Some("channel-96"));
    assert!(
        initial.is_enter_restricted.is_some() && initial.can_enter.is_some(),
        "permission info should be embedded in the initial full ChannelState"
    );

    let duplicate = bob
        .recv_until(
            |message| {
                matches!(message, Message::ChannelState(state)
                    if state.channel_id == Some(last_channel_id)
                        && (state.is_enter_restricted.is_some() || state.can_enter.is_some()))
            },
            Duration::from_millis(250),
        )
        .await;
    assert!(
        duplicate.is_none(),
        "permission-bearing channel state should not be resent after ServerSync"
    );
}

#[tokio::test]
async fn channel_state_permission_info_includes_inherited_restrictions() {
    let server = spawn_test_server(TestServerOpts {
        send_permission_info: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(71, "Child".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            0,
            true,
            vec![acl_for_group(
                "all",
                ACLPermissions::Enter.into(),
                ACLPermissions::Enter.into(),
                true,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let child = channel_permission_info(&bob, 71)
        .await
        .expect("child permission info");
    assert_eq!(child.is_enter_restricted, Some(true));
    assert_eq!(child.can_enter, Some(false));
}

async fn channel_permission_info(
    client: &TestClient,
    channel_id: u32,
) -> Option<shitspeak_proto::mumble_proto::ChannelState> {
    if let Some(channel) = client
        .initial_channel_states
        .iter()
        .find(|channel| {
            channel.channel_id == Some(channel_id) && channel.is_enter_restricted.is_some()
        })
        .cloned()
    {
        return Some(channel);
    }

    client
        .recv_until(
            |message| {
                matches!(
                    message,
                    Message::ChannelState(channel)
                        if channel.channel_id == Some(channel_id)
                            && channel.is_enter_restricted.is_some()
                )
            },
            Duration::from_secs(2),
        )
        .await
        .and_then(|message| match message {
            Message::ChannelState(channel) => Some(channel),
            _ => None,
        })
}

#[tokio::test]
async fn channel_state_permission_info_refreshes_after_acl_update() {
    let server = spawn_test_server(TestServerOpts {
        send_permission_info: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(69, "Private".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice.drain_now().await;
    bob.drain_now().await;

    alice
        .set_acls(
            69,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: false,
                inherited: false,
                user_id: None,
                group: Some("all".to_owned()),
                grant: 0,
                deny: ACLPermissions::Enter as u32,
            }],
            true,
        )
        .await;

    let refreshed = bob
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.channel_id == Some(69)
                        && cs.is_enter_restricted == Some(true)
                        && cs.can_enter == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        refreshed.is_some(),
        "Bob should receive refreshed ChannelState permission info after ACL update"
    );
}

#[tokio::test]
async fn channel_create_permission_info_does_not_refresh_existing_channels() {
    let server = spawn_test_server(TestServerOpts {
        send_permission_info: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(72, "Existing".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            72,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice.drain_now().await;
    bob.drain_now().await;

    alice.create_channel(0, "New Channel", false).await;

    let mut created_new_with_permission_info = false;
    let mut refreshed_existing = false;
    let mut global_flush = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline && !created_new_with_permission_info {
        let Some(message) = bob.recv(Duration::from_millis(100)).await else {
            continue;
        };
        global_flush |= matches!(&message, Message::PermissionQuery(pq) if pq.flush == Some(true));
        created_new_with_permission_info |= matches!(&message, Message::ChannelState(cs)
            if cs.name.as_deref() == Some("New Channel")
                && cs.is_enter_restricted.is_some()
                && cs.can_enter.is_some());
        refreshed_existing |= matches!(&message, Message::ChannelState(cs)
            if cs.channel_id == Some(72)
                && cs.name.is_none()
                && cs.is_enter_restricted.is_some()
                && cs.can_enter.is_some());
    }
    assert!(
        created_new_with_permission_info,
        "Bob should receive permission info on the new channel's ChannelState"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    while tokio::time::Instant::now() < deadline {
        let Some(message) = bob.recv(Duration::from_millis(25)).await else {
            continue;
        };
        global_flush |= matches!(&message, Message::PermissionQuery(pq) if pq.flush == Some(true));
        refreshed_existing |= matches!(&message, Message::ChannelState(cs)
            if cs.channel_id == Some(72)
                && cs.name.is_none()
                && cs.is_enter_restricted.is_some()
                && cs.can_enter.is_some());
    }
    assert!(
        !global_flush,
        "Creating a channel should not flush every client's permission cache"
    );
    assert!(
        !refreshed_existing,
        "Creating a channel should not refresh permission info for unchanged existing channels"
    );
}

#[tokio::test]
async fn channel_state_permission_info_refreshes_only_affected_user_after_token_update() {
    let server = spawn_test_server(TestServerOpts {
        send_permission_info: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(70, "Door".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            70,
            true,
            vec![acl_for_group(
                "#@door",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    alice.drain_now().await;
    bob.drain_now().await;

    send_token_update(&bob, vec!["door"]).await;

    let bob_refresh = bob
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.channel_id == Some(70)
                        && cs.is_enter_restricted == Some(true)
                        && cs.can_enter == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        bob_refresh.is_some(),
        "Bob should receive refreshed ChannelState permission info after token update"
    );

    let alice_refresh = alice
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.channel_id == Some(70)
                        && cs.is_enter_restricted.is_some()
                        && cs.can_enter.is_some())
            },
            Duration::from_millis(250),
        )
        .await;
    assert!(
        alice_refresh.is_none(),
        "Alice should not receive Bob's per-user ChannelState permission refresh"
    );
}

#[tokio::test]
async fn channel_move_permission_info_refreshes_only_home_channel_dependent_acls() {
    let server = spawn_test_server(TestServerOpts {
        send_permission_info: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(73, "Lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(
            74,
            "Current Sensitive".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(75, "Static".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            74,
            true,
            vec![acl_for_group(
                "in",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();
    chans
        .set_acls(
            75,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.drain_now().await;

    bob.move_to_channel(74).await;

    let mut sensitive_refresh = false;
    let mut static_refresh = false;
    let mut global_flush = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline && !sensitive_refresh {
        let Some(message) = bob.recv(Duration::from_millis(100)).await else {
            continue;
        };
        global_flush |= matches!(&message, Message::PermissionQuery(pq) if pq.flush == Some(true));
        sensitive_refresh |= matches!(&message, Message::ChannelState(cs)
            if cs.channel_id == Some(74)
                && cs.is_enter_restricted == Some(true)
                && cs.can_enter == Some(false));
        static_refresh |= matches!(&message, Message::ChannelState(cs)
            if cs.channel_id == Some(75)
                && cs.is_enter_restricted.is_some()
                && cs.can_enter.is_some());
    }
    assert!(
        sensitive_refresh,
        "Bob should receive a permission-info refresh for the channel with an `in` ACL"
    );
    assert!(
        !global_flush,
        "Bob should not receive a global permission flush for a pure channel move"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    while tokio::time::Instant::now() < deadline {
        let Some(message) = bob.recv(Duration::from_millis(25)).await else {
            continue;
        };
        global_flush |= matches!(&message, Message::PermissionQuery(pq) if pq.flush == Some(true));
        static_refresh |= matches!(&message, Message::ChannelState(cs)
            if cs.channel_id == Some(75)
                && cs.is_enter_restricted.is_some()
                && cs.can_enter.is_some());
    }
    assert!(
        !global_flush,
        "Bob should not receive a delayed global permission flush for a pure channel move"
    );
    assert!(
        !static_refresh,
        "Bob should not receive a permission-info refresh for static ACLs on a channel move"
    );
}

#[tokio::test]
async fn channel_move_permission_info_refresh_scope_includes_inherited_sub_acls() {
    let server = spawn_test_server(TestServerOpts {
        send_permission_info: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(76, "Fleet".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(77, "Squad".to_owned(), 0, 0, Some(76)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(78, "Command".to_owned(), 0, 0, Some(76)))
        .await
        .unwrap();
    chans
        .set_acls(
            76,
            true,
            vec![acl_for_group(
                "~sub",
                ACLPermissions::Enter.into(),
                enumflags2::BitFlags::empty(),
                true,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    bob.drain_now().await;

    bob.move_to_channel(77).await;

    let scoped_permission_refresh = bob
        .recv_until(
            |m| {
                matches!(m, Message::PermissionQuery(pq)
                    if pq.channel_id == Some(78)
                        && pq.permissions.is_some()
                        && pq.flush == Some(false))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        scoped_permission_refresh.is_some(),
        "Bob should receive a channel-scoped permission refresh for a non-entered affected channel"
    );

    let command_refresh = bob
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.channel_id == Some(78)
                        && cs.is_enter_restricted.is_some()
                        && cs.can_enter.is_some())
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        command_refresh.is_some(),
        "Bob should receive refreshes for descendants whose inherited ACL chain contains `sub`"
    );
}

#[tokio::test]
async fn superuser_speak_and_whisper_follow_acl_evaluation() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let initial = cached_permissions(&server, &alice, 0).await;
    assert!(initial.contains(ACLPermissions::Speak));
    assert!(initial.contains(ACLPermissions::Whisper));
    assert!(initial.contains(ACLPermissions::Ban));

    server
        .server
        .get_channels()
        .set_acls(
            0,
            true,
            vec![acl_for_group(
                "all",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Speak | ACLPermissions::Whisper,
                true,
            )],
        )
        .await
        .unwrap();

    let after_deny = cached_permissions(&server, &alice, 0).await;
    assert!(!after_deny.contains(ACLPermissions::Speak));
    assert!(!after_deny.contains(ACLPermissions::Whisper));
    assert!(after_deny.contains(ACLPermissions::Ban));
}

#[tokio::test]
async fn acl_cache_parent_move_updates_inherited_permissions() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(54, "Open".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(55, "Restricted".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(56, "Child".to_owned(), 0, 0, Some(54)))
        .await
        .unwrap();
    chans
        .set_acls(
            55,
            true,
            vec![acl_for_group(
                "all",
                ACLPermissions::Enter.into(),
                ACLPermissions::Enter.into(),
                true,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let initial = cached_permissions(&server, &bob, 56).await;
    assert!(initial.contains(ACLPermissions::Enter));

    let mut patch = empty_channel_patch();
    patch.parent_id = Some(Some(55));
    chans.update_channel(56, patch).await.unwrap();

    let after = cached_permissions(&server, &bob, 56).await;
    assert!(!after.contains(ACLPermissions::Enter));
}

#[tokio::test]
async fn acl_cache_token_update_changes_permissions() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(57, "Token".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            57,
            true,
            vec![acl_for_group(
                "#@door",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let before = cached_permissions(&server, &bob, 57).await;
    assert!(before.contains(ACLPermissions::Enter));

    send_token_update(&bob, vec!["door"]).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let after = cached_permissions(&server, &bob, 57).await;
    assert!(!after.contains(ACLPermissions::Enter));
}

#[tokio::test]
async fn acl_cache_group_and_user_id_changes_update_permissions() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(58, "Identity".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            58,
            true,
            vec![acl_for_group(
                "special",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Enter.into(),
                false,
            )],
        )
        .await
        .unwrap();

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let client = connected_client(&server, &bob).await;

    let before = cached_permissions(&server, &bob, 58).await;
    assert!(before.contains(ACLPermissions::Enter));

    {
        let mut gs = client.write_global_state_direct();
        gs.set_groups(["special".to_owned()].into_iter().collect());
    }
    let after_group = cached_permissions(&server, &bob, 58).await;
    assert!(!after_group.contains(ACLPermissions::Enter));

    let superuser_before = cached_permissions(&server, &bob, 0).await;
    assert!(!superuser_before.contains(ACLPermissions::Ban));
    {
        let mut gs = client.write_global_state_direct();
        gs.set_superuser(true);
    }
    let superuser_after = cached_permissions(&server, &bob, 0).await;
    assert!(superuser_after.contains(ACLPermissions::Ban));
    {
        let mut gs = client.write_global_state_direct();
        gs.set_superuser(false);
    }

    chans
        .set_acls(
            58,
            true,
            vec![ACL {
                user_id: Some(2),
                group: None,
                apply_here: true,
                apply_subs: false,
                allow: enumflags2::BitFlags::empty(),
                deny: ACLPermissions::Enter.into(),
            }],
        )
        .await
        .unwrap();

    let user_before = cached_permissions(&server, &bob, 58).await;
    assert_eq!(client.get_user_id(), Some(2));
    assert!(!user_before.contains(ACLPermissions::Enter));
    {
        let mut gs = client.write_global_state_direct();
        gs.set_user_id(Some(99));
    }
    let user_after = cached_permissions(&server, &bob, 58).await;
    assert_eq!(client.get_user_id(), Some(99));
    assert!(user_after.contains(ACLPermissions::Enter));
}

#[tokio::test]
async fn acl_cache_missing_channel_result_is_not_cached() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let missing = cached_permissions(&server, &bob, 59).await;
    assert!(missing.is_empty());

    server
        .server
        .get_channels()
        .create_channel(Channel::new(59, "Later".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let after = cached_permissions(&server, &bob, 59).await;
    assert!(after.contains(ACLPermissions::Enter));
}
