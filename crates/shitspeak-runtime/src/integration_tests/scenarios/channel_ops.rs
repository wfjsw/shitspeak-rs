//! Channel CRUD scenarios.

use std::time::Duration;

use crate::acl::{ACL, ACLPermissions};
use crate::channel_handler::{ChannelTreeShadow, SessionChannelShadow, replay_channel_log_gap};
use crate::channels::Channel;
use crate::client::visibility::UserVisibilityState;
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::messages::Message;
use crate::messages::encoder::{ChannelState, DenyType};
use crate::types::DEFAULT_SERVER_ID;

async fn create_channel_and_wait(
    client: &TestClient,
    parent: u32,
    name: &str,
    temporary: bool,
) -> u32 {
    client.create_channel(parent, name, temporary).await;

    let created = client
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.name.as_deref() == Some(name)
                        && cs.temporary == Some(temporary)
                        && cs.channel_id.is_some())
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap_or_else(|| panic!("client should observe channel creation for {name}"));

    match created {
        Message::ChannelState(cs) => cs.channel_id.expect("created channel id"),
        other => panic!("expected ChannelState, got {other:?}"),
    }
}

async fn wait_for_user_in_channel(client: &TestClient, session_id: u32, channel_id: u32) {
    let moved = client
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(session_id) && us.channel_id == Some(channel_id))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        moved.is_some(),
        "session {session_id} should move into channel {channel_id}"
    );
}

async fn expect_temporary_parent_denied(client: &TestClient, temp_channel_id: u32, context: &str) {
    let denied = client
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.r#type == Some(DenyType::TemporaryChannel as i32)
                        && pd.channel_id == Some(temp_channel_id))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(denied.is_some(), "{context}");
}

async fn reparent_channel(client: &TestClient, channel_id: u32, parent: u32) {
    client
        .send(
            ChannelState {
                channel_id: Some(channel_id),
                parent: Some(parent),
                name: None,
                links: Vec::new(),
                description: None,
                links_add: Vec::new(),
                links_remove: Vec::new(),
                temporary: None,
                position: None,
                description_hash: None,
                max_users: None,
                is_enter_restricted: None,
                can_enter: None,
            }
            .into(),
        )
        .await;
}

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

#[tokio::test]
async fn creating_temp_channel_moves_creator_into_it() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    alice.create_channel(0, "ScratchTemp", true).await;

    let created = alice
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.name.as_deref() == Some("ScratchTemp")
                        && cs.temporary == Some(true)
                        && cs.channel_id.is_some())
            },
            Duration::from_secs(2),
        )
        .await
        .expect("Alice should observe the temporary channel creation");
    let temp_channel_id = match created {
        Message::ChannelState(cs) => cs.channel_id.expect("created channel id"),
        other => panic!("expected ChannelState, got {other:?}"),
    };

    assert_ne!(
        temp_channel_id & 0x8000_0000,
        0,
        "temporary channels must use the temporary channel id range"
    );
    assert_eq!(
        server
            .server
            .get_clients()
            .get_local_clients_in_channel(temp_channel_id)
            .await
            .iter()
            .map(|client| u32::from(client.get_session_id()))
            .collect::<Vec<_>>(),
        vec![alice.session_id],
        "creator should be in the temp channel as soon as creation is visible"
    );

    let moved = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id)
                        && us.channel_id == Some(temp_channel_id))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        moved.is_some(),
        "creator should receive the move into the temporary channel immediately after creation"
    );
}

#[tokio::test]
async fn temp_channel_creation_grants_only_missing_creator_permissions() {
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
            vec![
                ACL {
                    user_id: None,
                    group: Some("all".to_owned()),
                    apply_here: true,
                    apply_subs: true,
                    allow: enumflags2::BitFlags::empty(),
                    deny: ACLPermissions::Enter | ACLPermissions::Speak,
                },
                ACL {
                    user_id: Some(1),
                    group: None,
                    apply_here: true,
                    apply_subs: true,
                    allow: ACLPermissions::TempChannel | ACLPermissions::Enter,
                    deny: enumflags2::BitFlags::empty(),
                },
            ],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let temp_channel_id = create_channel_and_wait(&alice, 0, "AclTemp", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;

    let channel = server
        .server
        .get_channels()
        .get_channel_in_server(DEFAULT_SERVER_ID, temp_channel_id)
        .await
        .expect("temporary channel should exist");
    let creator_acl = channel
        .acls
        .iter()
        .find(|acl| acl.user_id == Some(1))
        .expect("temp channel should add a creator ACL for missing permissions");

    assert_eq!(
        creator_acl.allow,
        ACLPermissions::Write | ACLPermissions::Speak,
        "Enter is inherited, so only missing Write and Speak should be granted locally"
    );
    assert!(creator_acl.deny.is_empty());
    assert!(creator_acl.apply_here);
    assert!(!creator_acl.apply_subs);
}

#[tokio::test]
async fn temp_channel_creation_does_not_duplicate_inherited_creator_permissions() {
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
            vec![
                ACL {
                    user_id: None,
                    group: Some("all".to_owned()),
                    apply_here: true,
                    apply_subs: true,
                    allow: enumflags2::BitFlags::empty(),
                    deny: ACLPermissions::Enter | ACLPermissions::Speak,
                },
                ACL {
                    user_id: Some(1),
                    group: None,
                    apply_here: true,
                    apply_subs: true,
                    allow: ACLPermissions::TempChannel
                        | ACLPermissions::Write
                        | ACLPermissions::Enter
                        | ACLPermissions::Speak,
                    deny: enumflags2::BitFlags::empty(),
                },
            ],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let temp_channel_id = create_channel_and_wait(&alice, 0, "InheritedAclTemp", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;

    let channel = server
        .server
        .get_channels()
        .get_channel_in_server(DEFAULT_SERVER_ID, temp_channel_id)
        .await
        .expect("temporary channel should exist");

    assert!(
        channel.acls.iter().all(|acl| acl.user_id != Some(1)),
        "creator permissions already inherited by the temporary channel should not be duplicated"
    );
}

#[tokio::test]
async fn temp_channel_creator_acl_grant_can_be_disabled() {
    let server = spawn_test_server(TestServerOpts {
        grant_temp_channel_creator_acl: false,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    server
        .server
        .get_channels()
        .set_acls(
            0,
            true,
            vec![
                ACL {
                    user_id: None,
                    group: Some("all".to_owned()),
                    apply_here: true,
                    apply_subs: true,
                    allow: enumflags2::BitFlags::empty(),
                    deny: ACLPermissions::Enter | ACLPermissions::Speak,
                },
                ACL {
                    user_id: Some(1),
                    group: None,
                    apply_here: true,
                    apply_subs: true,
                    allow: ACLPermissions::TempChannel.into(),
                    deny: enumflags2::BitFlags::empty(),
                },
            ],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let temp_channel_id = create_channel_and_wait(&alice, 0, "NoCreatorAclTemp", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;

    let channel = server
        .server
        .get_channels()
        .get_channel_in_server(DEFAULT_SERVER_ID, temp_channel_id)
        .await
        .expect("temporary channel should exist");

    assert!(
        channel.acls.is_empty(),
        "disabled grant_temp_channel_creator_acl should leave the temp channel without creator ACLs"
    );
}

#[tokio::test]
async fn temp_channel_creation_grants_certificate_hash_acl_without_user_id() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, None, vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let expected_group = format!("${}", hex::encode(alice.cert_sha1()));

    server
        .server
        .get_channels()
        .set_acls(
            0,
            true,
            vec![
                ACL {
                    user_id: None,
                    group: Some("all".to_owned()),
                    apply_here: true,
                    apply_subs: true,
                    allow: enumflags2::BitFlags::empty(),
                    deny: ACLPermissions::Enter | ACLPermissions::Speak,
                },
                ACL {
                    user_id: None,
                    group: Some(expected_group.clone()),
                    apply_here: true,
                    apply_subs: true,
                    allow: ACLPermissions::TempChannel.into(),
                    deny: enumflags2::BitFlags::empty(),
                },
            ],
        )
        .await
        .unwrap();

    let temp_channel_id = create_channel_and_wait(&alice, 0, "CertAclTemp", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;

    let channel = server
        .server
        .get_channels()
        .get_channel_in_server(DEFAULT_SERVER_ID, temp_channel_id)
        .await
        .expect("temporary channel should exist");
    let creator_acl = channel
        .acls
        .iter()
        .find(|acl| acl.group.as_deref() == Some(expected_group.as_str()))
        .expect("temp channel should add a certificate-hash ACL for anonymous creators");

    assert_eq!(
        creator_acl.allow,
        ACLPermissions::Write | ACLPermissions::Enter | ACLPermissions::Speak
    );
    assert!(creator_acl.deny.is_empty());
    assert_eq!(creator_acl.user_id, None);
    assert!(creator_acl.apply_here);
    assert!(!creator_acl.apply_subs);
}

#[tokio::test]
async fn temp_channels_cannot_be_parents_for_create_or_reparent() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let temp_channel_id = create_channel_and_wait(&alice, 0, "ScratchParent", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;

    alice.create_channel(temp_channel_id, "Nested", false).await;
    expect_temporary_parent_denied(
        &alice,
        temp_channel_id,
        "creating a child channel under a temporary parent should be rejected",
    )
    .await;

    let permanent_channel_id = create_channel_and_wait(&alice, 0, "PermanentMove", false).await;
    reparent_channel(&alice, permanent_channel_id, temp_channel_id).await;
    expect_temporary_parent_denied(
        &alice,
        temp_channel_id,
        "moving an existing channel under a temporary parent should be rejected",
    )
    .await;
}

#[tokio::test]
async fn temp_channel_is_removed_after_last_user_moves_out() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let temp_channel_id = create_channel_and_wait(&alice, 0, "MoveCleanup", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;

    alice.move_to_channel(0).await;

    let removed = alice
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == temp_channel_id),
            Duration::from_secs(3),
        )
        .await;
    assert!(
        removed.is_some(),
        "empty temporary channel should be removed after the creator moves out"
    );
    assert!(
        server
            .server
            .get_channels()
            .get_channel_in_server(DEFAULT_SERVER_ID, temp_channel_id)
            .await
            .is_none(),
        "temporary channel should be gone from the repository"
    );
}

#[tokio::test]
async fn temp_channel_is_removed_after_last_user_disconnects() {
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

    let temp_channel_id = create_channel_and_wait(&alice, 0, "DisconnectCleanup", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;

    drop(alice);

    let removed = bob
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == temp_channel_id),
            Duration::from_secs(5),
        )
        .await;
    assert!(
        removed.is_some(),
        "empty temporary channel should be removed after the last user disconnects"
    );
    assert!(
        server
            .server
            .get_channels()
            .get_channel_in_server(DEFAULT_SERVER_ID, temp_channel_id)
            .await
            .is_none(),
        "temporary channel should be gone from the repository"
    );
}

#[tokio::test]
async fn simultaneous_temporary_channels_get_distinct_ids() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_superuser("bob", None, Some(2), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let alice_temp = create_channel_and_wait(&alice, 0, "AliceTemp", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, alice_temp).await;
    let bob_temp = create_channel_and_wait(&bob, 0, "BobTemp", true).await;
    wait_for_user_in_channel(&bob, bob.session_id, bob_temp).await;

    assert_ne!(
        alice_temp, bob_temp,
        "active temporary channels must not reuse the same id"
    );
    assert_eq!(
        server
            .server
            .get_channels()
            .get_channel_in_server(DEFAULT_SERVER_ID, alice_temp)
            .await
            .expect("Alice temp channel should still exist")
            .name,
        "AliceTemp"
    );
    assert_eq!(
        server
            .server
            .get_channels()
            .get_channel_in_server(DEFAULT_SERVER_ID, bob_temp)
            .await
            .expect("Bob temp channel should exist")
            .name,
        "BobTemp"
    );
}

#[tokio::test]
async fn channel_dependency_gap_replays_missing_create_before_user_move() {
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

    let before_create = server
        .server
        .get_channels()
        .current_version_in_server(DEFAULT_SERVER_ID);
    let temp_channel_id = create_channel_and_wait(&alice, 0, "DependencyReplayTemp", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;

    let create_version = server
        .server
        .get_channels()
        .current_version_in_server(DEFAULT_SERVER_ID);
    assert_eq!(
        create_version,
        before_create + 1,
        "precondition: temp channel create should advance channel version once"
    );

    let bob_server_client = server
        .server
        .get_clients()
        .get_client_in_server(DEFAULT_SERVER_ID, bob.server_session)
        .await
        .expect("server-side bob client");
    let _ = bob.drain_now().await;
    bob_server_client
        .set_last_channel_version(before_create)
        .await;

    let mut channel_tree_shadow = ChannelTreeShadow::default();
    channel_tree_shadow.insert(0);
    let mut session_channel_shadow = SessionChannelShadow::new();
    session_channel_shadow.insert(alice.server_session, 0);
    session_channel_shadow.insert(bob.server_session, 0);
    let mut user_visibility = UserVisibilityState::default();

    replay_channel_log_gap(
        &server.server,
        &bob_server_client,
        server.server.get_channels(),
        &mut channel_tree_shadow,
        &mut session_channel_shadow,
        &mut user_visibility,
        bob_server_client.get_session_id(),
        before_create,
        create_version + 1,
    )
    .await
    .expect("client-state dependency gap should replay the missing channel create");

    let replayed_create = bob
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.channel_id == Some(temp_channel_id)
                        && cs.name.as_deref() == Some("DependencyReplayTemp"))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        replayed_create.is_some(),
        "viewer should receive the missing channel create before the dependent user move"
    );
    assert_eq!(
        bob_server_client.get_last_channel_version().await,
        create_version
    );
    assert!(
        !bob.recv_closed(Duration::from_millis(200)).await,
        "replaying a one-op channel dependency gap should keep the viewer connected"
    );
}

#[tokio::test]
async fn temp_channel_log_gap_snapshot_removes_stale_channel_without_disconnect() {
    let server = spawn_test_server(TestServerOpts {
        channel_log_max_entries: 1,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let temp_channel_id = create_channel_and_wait(&alice, 0, "ReplayGapTemp", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;
    let stale_version = server
        .server
        .get_channels()
        .current_version_in_server(DEFAULT_SERVER_ID);

    alice.move_to_channel(0).await;
    let removed = alice
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == temp_channel_id),
            Duration::from_secs(3),
        )
        .await;
    assert!(
        removed.is_some(),
        "precondition: temporary channel should be removed before replay check"
    );
    create_channel_and_wait(&alice, 0, "ReplayGapAfter", false).await;
    let _ = alice.drain_now().await;

    let server_client = server
        .server
        .get_clients()
        .get_client_in_server(DEFAULT_SERVER_ID, alice.server_session)
        .await
        .expect("server-side alice client");
    let latest = server
        .server
        .get_channels()
        .current_version_in_server(DEFAULT_SERVER_ID);
    assert!(
        latest > stale_version + 1,
        "precondition: temp cleanup and follow-up channel create should advance channel log"
    );
    let retained = server
        .server
        .get_channels()
        .get_log_since_in_server(DEFAULT_SERVER_ID, stale_version)
        .await;
    assert!(
        retained
            .first()
            .is_some_and(|entry| entry.version > stale_version + 1),
        "precondition: bounded channel log should no longer contain the start of the gap"
    );
    server_client.set_last_channel_version(stale_version).await;

    let mut channel_tree_shadow = ChannelTreeShadow::default();
    channel_tree_shadow.insert(0);
    channel_tree_shadow.insert(temp_channel_id);
    let mut session_channel_shadow = SessionChannelShadow::new();
    session_channel_shadow.insert(alice.server_session, 0);
    let mut user_visibility = UserVisibilityState::default();

    replay_channel_log_gap(
        &server.server,
        &server_client,
        server.server.get_channels(),
        &mut channel_tree_shadow,
        &mut session_channel_shadow,
        &mut user_visibility,
        server_client.get_session_id(),
        stale_version,
        u64::MAX,
    )
    .await
    .expect("channel replay gap should recover by sending a snapshot");

    let snapshot_removed_stale_temp = alice
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == temp_channel_id),
            Duration::from_secs(2),
        )
        .await;
    assert!(
        snapshot_removed_stale_temp.is_some(),
        "snapshot replay should remove a stale temporary channel from the socket's view"
    );

    assert!(
        !alice.recv_closed(Duration::from_millis(200)).await,
        "recovering an empty channel replay window should keep the client connected"
    );
}

#[tokio::test]
async fn temp_channel_lagged_replay_when_already_current_is_recoverable() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    let temp_channel_id = create_channel_and_wait(&alice, 0, "LaggedReplayTemp", true).await;
    wait_for_user_in_channel(&alice, alice.session_id, temp_channel_id).await;
    alice.move_to_channel(0).await;

    let removed = alice
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == temp_channel_id),
            Duration::from_secs(3),
        )
        .await;
    assert!(
        removed.is_some(),
        "precondition: interacting with a temporary channel should remove it"
    );

    let server_client = server
        .server
        .get_clients()
        .get_client_in_server(DEFAULT_SERVER_ID, alice.server_session)
        .await
        .expect("server-side alice client");
    let latest = server
        .server
        .get_channels()
        .current_version_in_server(DEFAULT_SERVER_ID);
    server_client.set_last_channel_version(latest).await;

    let mut channel_tree_shadow = ChannelTreeShadow::default();
    channel_tree_shadow.insert(0);
    let mut session_channel_shadow = SessionChannelShadow::new();
    session_channel_shadow.insert(alice.server_session, 0);
    let mut user_visibility = UserVisibilityState::default();

    replay_channel_log_gap(
        &server.server,
        &server_client,
        server.server.get_channels(),
        &mut channel_tree_shadow,
        &mut session_channel_shadow,
        &mut user_visibility,
        server_client.get_session_id(),
        latest,
        u64::MAX,
    )
    .await
    .expect("a lagged channel replay should be a no-op when the client is already current");

    assert!(
        !alice.recv_closed(Duration::from_millis(200)).await,
        "lagged replay after temporary-channel activity should not disconnect the client"
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
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
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
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
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

#[tokio::test]
async fn remove_channel_migrates_users_to_first_enterable_fallback() {
    let server = spawn_test_server(TestServerOpts {
        default_channel: 30,
        debug_acl_enter: false,
        explicit_enter_deny_overrides_write: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(30, "Lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(40, "DeniedParent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(41, "Doomed".to_owned(), 0, 0, Some(40)))
        .await
        .unwrap();
    let deny_enter = ACL {
        user_id: None,
        group: Some("all".to_owned()),
        apply_here: true,
        apply_subs: false,
        allow: enumflags2::BitFlags::empty(),
        deny: ACLPermissions::Enter.into(),
    };
    chans
        .set_acls(0, true, vec![deny_enter.clone()])
        .await
        .unwrap();
    chans.set_acls(40, true, vec![deny_enter]).await.unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let alice_session = alice.session_id;

    alice.move_to_channel(41).await;
    let _ = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session) && us.channel_id == Some(41))
            },
            Duration::from_secs(2),
        )
        .await;

    alice.remove_channel(41).await;

    let moved = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session) && us.channel_id == Some(30))
            },
            Duration::from_secs(3),
        )
        .await;
    assert!(
        moved.is_some(),
        "Alice should be moved to the default channel when the deleted channel's parent and root deny Enter"
    );

    let moved_to_denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session)
                        && (us.channel_id == Some(40) || us.channel_id == Some(0)))
            },
            Duration::from_millis(300),
        )
        .await;
    assert!(
        moved_to_denied.is_none(),
        "Alice should not be moved into the denied parent or root channel"
    );
}
