//! ACL scenarios: write an ACL that denies Enter on a sub-channel; the
//! restricted client gets a `PermissionDenied` and stays in their original
//! channel.

use std::time::Duration;

use bytes::Bytes;

use crate::acl::{ACL, ACLPermissions};
use crate::channels::{Channel, ChannelPatch};
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::messages::Message;
use crate::messages::encoder::{
    Authenticate, ChanAcl, ClientType, PluginDataTransmission, TextMessage, UserState, UserStats,
    VoiceTarget,
};

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
        targets: vec![crate::mumble_proto::voice_target::Target {
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
        crate::messages::encoder::PermissionQuery {
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
    assert_eq!(permissions & ACLPermissions::TextMessage as u32, 0);
}

#[tokio::test]
async fn superuser_speak_and_whisper_follow_acl_evaluation() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);

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

    let admin_before = cached_permissions(&server, &bob, 0).await;
    assert!(!admin_before.contains(ACLPermissions::Ban));
    {
        let mut gs = client.write_global_state_direct();
        gs.set_groups(["admin".to_owned()].into_iter().collect());
    }
    let admin_after = cached_permissions(&server, &bob, 0).await;
    assert!(admin_after.contains(ACLPermissions::Ban));
    {
        let mut gs = client.write_global_state_direct();
        gs.set_groups(std::collections::HashSet::new());
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
