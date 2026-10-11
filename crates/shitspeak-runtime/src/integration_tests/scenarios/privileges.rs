//! Authenticator-assigned privileges: each privilege grants one capability
//! outside of the channel ACL model without making the user a superuser.

use std::time::Duration;

use bytes::Bytes;

use crate::integration_tests::harness::{
    TestClient, TestServer, TestServerOpts, spawn_test_server,
};
use shitspeak_auth::Privilege;
use shitspeak_messages::messages::Message;
use shitspeak_messages::messages::encoder::{PermissionQuery, TextMessage, UserState, VoiceTarget};
use shitspeak_proto::mumble_proto::voice_target::Target as VoiceTargetEntry;
use shitspeak_state::{ACL, ACLPermissions, Channel};

const DEADLINE: Duration = Duration::from_secs(2);
const QUIET: Duration = Duration::from_millis(300);

async fn connect(server: &TestServer, name: &str) -> TestClient {
    TestClient::connect_and_authenticate(server, name, None)
        .await
        .unwrap_or_else(|error| panic!("{name} should authenticate: {error:?}"))
}

async fn create_channel(server: &TestServer, channel_id: u32, name: &str) {
    server
        .server
        .get_channels()
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(channel_id, name.to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();
}

async fn deny_for_all(server: &TestServer, channel_id: u32, deny: ACLPermissions) {
    deny_for_group(server, channel_id, "all", deny).await;
}

async fn deny_for_group(server: &TestServer, channel_id: u32, group: &str, deny: ACLPermissions) {
    server
        .server
        .get_channels()
        .set_acls_in_server(
            crate::types::DEFAULT_SERVER_ID,
            channel_id,
            true,
            vec![ACL {
                user_id: None,
                group: Some(group.to_owned()),
                apply_here: true,
                apply_subs: true,
                allow: enumflags2::BitFlags::empty(),
                deny: deny.into(),
            }],
        )
        .await
        .unwrap();
}

async fn expect_denied(client: &TestClient, permission: ACLPermissions, what: &str) {
    let denied = client
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.permission == Some(permission as u32))
            },
            DEADLINE,
        )
        .await;
    assert!(denied.is_some(), "{what} should be denied {permission:?}");
}

async fn expect_not_denied(client: &TestClient, what: &str) {
    let denied = client
        .recv_until(|m| matches!(m, Message::PermissionDenied(_)), QUIET)
        .await;
    assert!(denied.is_none(), "{what} must not be denied: {denied:?}");
}

async fn expect_user_state(
    client: &TestClient,
    what: &str,
    mut predicate: impl FnMut(&shitspeak_proto::mumble_proto::UserState) -> bool,
) -> shitspeak_proto::mumble_proto::UserState {
    match client
        .recv_until(
            |m| matches!(m, Message::UserState(us) if predicate(us)),
            DEADLINE,
        )
        .await
    {
        Some(Message::UserState(state)) => state,
        other => panic!("{what}: expected UserState, got {other:?}"),
    }
}

async fn live_client(
    server: &TestServer,
    client: &TestClient,
) -> std::sync::Arc<Box<crate::client::Client>> {
    server
        .server
        .get_clients()
        .get_client_in_server(crate::types::DEFAULT_SERVER_ID, client.server_session)
        .await
        .expect("live client")
}

#[tokio::test]
async fn mute_deafen_privilege_bypasses_acl_without_granting_suppress() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::MuteDeafen],
    );
    server
        .authenticator
        .register_user("dave", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);

    let carol = connect(&server, "carol").await;
    let dave = connect(&server, "dave").await;
    let bob = connect(&server, "bob").await;

    dave.mute_other(bob.session_id, true).await;
    expect_denied(&dave, ACLPermissions::MuteDeafen, "an unprivileged mute").await;

    carol.deaf_other(bob.session_id, true).await;
    let state = expect_user_state(&bob, "privileged deafen", |us| {
        us.session == Some(bob.session_id) && us.deaf == Some(true)
    })
    .await;
    assert_eq!(state.mute, Some(true), "deafening also mutes");
    expect_not_denied(&carol, "a privileged deafen").await;

    carol.suppress_other(bob.session_id, true).await;
    expect_denied(
        &carol,
        ACLPermissions::MuteDeafen,
        "suppress without its privilege",
    )
    .await;

    // Mute and suppression are independent, so an unmute keeps Bob
    // suppressed.
    let live_bob = live_client(&server, &bob).await;
    {
        let mut state = live_bob.write_global_state(server.server.get_clients());
        state.set_suppress(true);
    }
    carol.mute_other(bob.session_id, false).await;
    expect_user_state(&bob, "privileged unmute", |us| {
        us.session == Some(bob.session_id) && us.mute == Some(false)
    })
    .await;
    let state = live_bob.read_global_state();
    assert!(!state.is_muted());
    assert!(!state.is_deafened());
    assert!(state.is_suppressed(), "an unmute must not unsuppress");
}

#[tokio::test]
async fn suppress_privilege_bypasses_acl_without_granting_mute() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::Suppress],
    );
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let carol = connect(&server, "carol").await;
    let bob = connect(&server, "bob").await;

    carol.suppress_other(bob.session_id, true).await;
    expect_user_state(&bob, "privileged suppress", |us| {
        us.session == Some(bob.session_id) && us.suppress == Some(true)
    })
    .await;
    carol.suppress_other(bob.session_id, false).await;
    expect_user_state(&bob, "privileged unsuppress", |us| {
        us.session == Some(bob.session_id) && us.suppress == Some(false)
    })
    .await;
    expect_not_denied(&carol, "privileged suppression").await;

    carol.mute_other(bob.session_id, true).await;
    expect_denied(
        &carol,
        ACLPermissions::MuteDeafen,
        "mute without its privilege",
    )
    .await;
}

#[tokio::test]
async fn priority_speaker_privilege_bypasses_acl() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::PrioritySpeaker],
    );
    server
        .authenticator
        .register_user("dave", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);

    let carol = connect(&server, "carol").await;
    let dave = connect(&server, "dave").await;
    let bob = connect(&server, "bob").await;
    let priority = |value| {
        Message::from(UserState {
            session: Some(bob.server_session),
            priority_speaker: Some(value),
            ..Default::default()
        })
    };

    dave.send(priority(true)).await;
    expect_denied(
        &dave,
        ACLPermissions::MuteDeafen,
        "unprivileged priority speaker",
    )
    .await;

    carol.send(priority(true)).await;
    expect_user_state(&bob, "privileged priority speaker", |us| {
        us.session == Some(bob.session_id) && us.priority_speaker == Some(true)
    })
    .await;
    expect_not_denied(&carol, "privileged priority speaker").await;

    carol.mute_other(bob.session_id, true).await;
    expect_denied(
        &carol,
        ACLPermissions::MuteDeafen,
        "mute without its privilege",
    )
    .await;
}

#[tokio::test]
async fn move_privilege_bypasses_acl() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    create_channel(&server, 50, "Destination").await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::Move],
    );
    server
        .authenticator
        .register_user("dave", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);

    let carol = connect(&server, "carol").await;
    let dave = connect(&server, "dave").await;
    let bob = connect(&server, "bob").await;

    dave.move_other(bob.session_id, 50).await;
    expect_denied(&dave, ACLPermissions::Move, "an unprivileged move").await;

    carol.move_other(bob.session_id, 50).await;
    expect_user_state(&bob, "privileged move", |us| {
        us.session == Some(bob.session_id) && us.channel_id == Some(50)
    })
    .await;
    expect_not_denied(&carol, "a privileged move").await;
}

#[tokio::test]
async fn server_moderation_privilege_attributes_actions_to_the_server() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .set_privileges("alice", [Privilege::ServerModeration]);
    server
        .authenticator
        .register_superuser("sam", None, Some(2), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);
    server
        .authenticator
        .register_user("eve", None, Some(4), vec![]);

    let alice = connect(&server, "alice").await;
    let sam = connect(&server, "sam").await;
    let bob = connect(&server, "bob").await;
    let eve = connect(&server, "eve").await;
    assert!(
        bob.initial_user_states
            .iter()
            .any(|state| state.session == Some(alice.session_id)),
        "server_moderation alone must not hide the moderator"
    );

    alice.mute_other(bob.session_id, true).await;
    for (observer, name) in [(&bob, "target"), (&sam, "superuser"), (&eve, "user")] {
        let state = expect_user_state(observer, name, |us| {
            us.session == Some(bob.session_id) && us.mute == Some(true)
        })
        .await;
        assert_eq!(
            state.actor, None,
            "the {name} observer must not see the actor"
        );
    }

    alice.kick(eve.session_id, "server moderation kick").await;
    for (observer, name) in [(&eve, "target"), (&sam, "superuser"), (&bob, "user")] {
        let remove = observer
            .recv_until(
                |m| {
                    matches!(m, Message::UserRemove(remove)
                        if remove.session == eve.session_id
                            && remove.reason.as_deref() == Some("server moderation kick"))
                },
                DEADLINE,
            )
            .await;
        let Some(Message::UserRemove(remove)) = remove else {
            panic!("the {name} observer should receive the kick");
        };
        assert_eq!(
            remove.actor, None,
            "the {name} observer must not see the actor"
        );
    }
}

/// Regression: an invisible moderator's UserState action used to carry its
/// session as actor to superusers, whose user projection is unfiltered.
#[tokio::test]
async fn invisible_moderator_state_action_hides_actor_from_superusers() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_invisible_superuser("ghost", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_superuser("sam", None, Some(2), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);

    let ghost = connect(&server, "ghost").await;
    let sam = connect(&server, "sam").await;
    let bob = connect(&server, "bob").await;

    ghost.mute_other(bob.session_id, true).await;
    let state = expect_user_state(&sam, "superuser observer", |us| {
        us.session == Some(bob.session_id) && us.mute == Some(true)
    })
    .await;
    assert_eq!(
        state.actor, None,
        "the invisible moderator must not be revealed"
    );
}

#[tokio::test]
async fn server_text_privilege_attributes_text_to_the_server() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::ServerText],
    );
    server
        .authenticator
        .register_superuser("sam", None, Some(2), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);

    let carol = connect(&server, "carol").await;
    let sam = connect(&server, "sam").await;
    let bob = connect(&server, "bob").await;
    assert!(
        bob.initial_user_states
            .iter()
            .any(|state| state.session == Some(carol.session_id)),
        "server_text alone must not hide the sender"
    );

    carol
        .send(
            TextMessage {
                channel_id: vec![0],
                message: "announcement".to_owned(),
                ..TextMessage::default()
            }
            .into(),
        )
        .await;
    for (observer, name) in [(&bob, "user"), (&sam, "superuser")] {
        let text = observer
            .recv_until(
                |m| matches!(m, Message::TextMessage(t) if t.message == "announcement"),
                DEADLINE,
            )
            .await;
        let Some(Message::TextMessage(text)) = text else {
            panic!("the {name} should receive the text");
        };
        assert_eq!(text.actor, None, "the {name} must not see the sender");
    }
}

#[tokio::test]
async fn text_message_privilege_bypasses_acl() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    create_channel(&server, 60, "Quiet").await;
    deny_for_all(&server, 60, ACLPermissions::TextMessage).await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::TextMessage],
    );
    server
        .authenticator
        .register_user("dave", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);

    let carol = connect(&server, "carol").await;
    let dave = connect(&server, "dave").await;
    let bob = connect(&server, "bob").await;
    bob.move_to_channel(60).await;
    expect_user_state(&carol, "bob entering the quiet channel", |us| {
        us.session == Some(bob.session_id) && us.channel_id == Some(60)
    })
    .await;

    for (sender, text) in [(&dave, "denied"), (&carol, "allowed")] {
        sender
            .send(
                TextMessage {
                    channel_id: vec![60],
                    message: format!("{text} channel"),
                    ..TextMessage::default()
                }
                .into(),
            )
            .await;
        sender
            .send(
                TextMessage {
                    session: vec![bob.session_id],
                    message: format!("{text} direct"),
                    ..TextMessage::default()
                }
                .into(),
            )
            .await;
    }
    expect_denied(&dave, ACLPermissions::TextMessage, "unprivileged text").await;
    expect_not_denied(&carol, "privileged text").await;

    let mut received = Vec::new();
    while let Some(Message::TextMessage(text)) = bob
        .recv_until(|m| matches!(m, Message::TextMessage(_)), QUIET)
        .await
    {
        received.push(text.message);
    }
    received.sort();
    assert_eq!(received, vec!["allowed channel", "allowed direct"]);
}

#[tokio::test]
async fn edit_channels_privilege_bypasses_acl_but_not_removal_or_acl_edits() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::EditChannels],
    );
    server
        .authenticator
        .register_user("dave", None, Some(2), vec![]);

    let carol = connect(&server, "carol").await;
    let dave = connect(&server, "dave").await;

    dave.create_channel(0, "Unprivileged", false).await;
    expect_denied(&dave, ACLPermissions::MakeChannel, "an unprivileged create").await;

    carol.create_channel(0, "Privileged", false).await;
    let created = dave
        .recv_until(
            |m| matches!(m, Message::ChannelState(cs) if cs.name.as_deref() == Some("Privileged")),
            DEADLINE,
        )
        .await;
    let Some(Message::ChannelState(created)) = created else {
        panic!("the privileged create should be published");
    };
    let channel_id = created.channel_id.expect("created channel id");

    carol.update_channel_name(channel_id, "Renamed").await;
    dave.recv_until(
        |m| {
            matches!(m, Message::ChannelState(cs)
                if cs.channel_id == Some(channel_id) && cs.name.as_deref() == Some("Renamed"))
        },
        DEADLINE,
    )
    .await
    .expect("the privileged rename should be published");
    expect_not_denied(&carol, "privileged channel edits").await;

    carol.remove_channel(channel_id).await;
    expect_denied(&carol, ACLPermissions::Write, "channel removal").await;
    carol.set_acls(channel_id, Vec::new(), true).await;
    expect_denied(&carol, ACLPermissions::Write, "ACL editing").await;
    assert!(
        server
            .server
            .get_channels()
            .get_channel_in_server(crate::types::DEFAULT_SERVER_ID, channel_id)
            .await
            .is_some()
    );
}

#[tokio::test]
async fn see_all_privilege_ignores_visibility_rules_but_not_invisibility() {
    use crate::toggle_superuser_visibility::ACTION_ID;

    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    create_channel(&server, 70, "Secret").await;
    deny_for_group(&server, 70, "!secret", ACLPermissions::Traverse).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_invisible_user("ghost", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec!["secret".into()]);
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(4),
        vec![],
        [Privilege::SeeAll],
    );
    server
        .authenticator
        .register_user("dave", None, Some(5), vec![]);

    let alice = connect(&server, "alice").await;
    let ghost = connect(&server, "ghost").await;
    let bob = connect(&server, "bob").await;
    bob.move_to_channel(70).await;
    expect_user_state(&alice, "bob moved into the secret channel", |us| {
        us.session == Some(bob.session_id) && us.channel_id == Some(70)
    })
    .await;
    alice.trigger_context_action(ACTION_ID).await;
    let live_alice = live_client(&server, &alice).await;
    assert!(
        tokio::time::timeout(DEADLINE, async {
            while !live_alice.is_hidden_from_regular_users() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok(),
        "alice should enter hidden superuser mode"
    );

    let dave = connect(&server, "dave").await;
    let carol = connect(&server, "carol").await;

    let sees = |client: &TestClient, session: u32| {
        client
            .initial_user_states
            .iter()
            .any(|state| state.session == Some(session))
    };
    let sees_channel = |client: &TestClient, channel_id: u32| {
        client
            .initial_channel_states
            .iter()
            .any(|state| state.channel_id == Some(channel_id))
    };

    assert!(
        !sees_channel(&dave, 70),
        "control: dave cannot see the channel"
    );
    assert!(!sees(&dave, bob.session_id), "control: dave cannot see bob");
    assert!(
        !sees(&dave, alice.session_id),
        "control: dave cannot see alice"
    );

    assert!(sees_channel(&carol, 70), "see_all reveals hidden channels");
    assert!(
        sees(&carol, bob.session_id),
        "see_all reveals users in hidden channels"
    );
    assert!(
        sees(&carol, alice.session_id),
        "see_all reveals hidden superusers"
    );
    assert!(
        !sees(&carol, ghost.session_id),
        "invisible users stay invisible"
    );

    // Live updates reach the see_all viewer as well.
    bob.move_to_channel(0).await;
    bob.move_to_channel(70).await;
    expect_user_state(&carol, "bob re-entering the secret channel", |us| {
        us.session == Some(bob.session_id) && us.channel_id == Some(70)
    })
    .await;
}

#[tokio::test]
async fn privileges_widen_advertised_permissions() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::Move, Privilege::EditChannels],
    );
    server
        .authenticator
        .register_user("dave", None, Some(2), vec![]);

    let carol = connect(&server, "carol").await;
    let dave = connect(&server, "dave").await;

    let advertised = [
        ACLPermissions::Move,
        ACLPermissions::MakeChannel,
        ACLPermissions::Write,
    ];
    let root = carol.initial_permissions.expect("carol root permissions");
    let control = dave.initial_permissions.expect("dave root permissions");
    for permission in advertised {
        assert_ne!(
            root & permission as u64,
            0,
            "ServerSync advertises {permission:?}"
        );
        assert_eq!(
            control & permission as u64,
            0,
            "control lacks {permission:?}"
        );
    }
    assert_eq!(root & ACLPermissions::MuteDeafen as u64, 0);
    assert_eq!(root & ACLPermissions::Kick as u64, 0);

    carol
        .send(
            PermissionQuery {
                channel_id: Some(0),
                ..PermissionQuery::default()
            }
            .into(),
        )
        .await;
    let reply = carol
        .recv_until(
            |m| matches!(m, Message::PermissionQuery(query) if query.channel_id == Some(0) && query.permissions.is_some()),
            DEADLINE,
        )
        .await;
    let Some(Message::PermissionQuery(reply)) = reply else {
        panic!("carol should receive a permission reply");
    };
    let permissions = reply.permissions.expect("permissions");
    for permission in advertised {
        assert_ne!(
            permissions & permission as u32,
            0,
            "PermissionQuery advertises {permission:?}"
        );
    }
}

#[tokio::test]
async fn hide_self_privilege_grants_the_hide_me_toggle() {
    use crate::toggle_superuser_visibility::{ACTION_ID, HIDE_LABEL, SHOW_LABEL};

    let server = spawn_test_server(TestServerOpts::default()).await;
    server.authenticator.register_privileged_user(
        "carol",
        None,
        Some(1),
        vec![],
        [Privilege::HideSelf],
    );
    server
        .authenticator
        .register_user("dave", None, Some(2), vec![]);
    server
        .authenticator
        .register_superuser("sam", None, Some(3), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(4), vec![]);

    let carol = connect(&server, "carol").await;
    let dave = connect(&server, "dave").await;
    let sam = connect(&server, "sam").await;
    let bob = connect(&server, "bob").await;

    let offers_toggle = |client: &TestClient| {
        client
            .initial_context_actions
            .iter()
            .any(|action| action.action == ACTION_ID)
    };
    assert!(offers_toggle(&carol), "hide_self offers the toggle");
    assert!(
        !offers_toggle(&dave),
        "control: no toggle without the privilege"
    );

    // The toggle is ignored for a user without the privilege.
    dave.trigger_context_action(ACTION_ID).await;
    let live_dave = live_client(&server, &dave).await;
    tokio::time::sleep(QUIET).await;
    assert!(!live_dave.is_hidden_from_regular_users());

    carol.trigger_context_action(ACTION_ID).await;
    bob.recv_until(
        |m| matches!(m, Message::UserRemove(remove) if remove.session == carol.session_id),
        DEADLINE,
    )
    .await
    .expect("hiding removes carol for regular users");
    carol
        .recv_until(
            |m| {
                matches!(m, Message::ContextActionModify(modify)
                    if modify.action == ACTION_ID && modify.text.as_deref() == Some(SHOW_LABEL))
            },
            DEADLINE,
        )
        .await
        .expect("the toggle switches to Show me");
    let live_carol = live_client(&server, &carol).await;
    assert!(live_carol.is_hidden_from_regular_users());
    assert!(live_carol.read_global_state().is_suppressed());
    let sam_removed = sam
        .recv_until(
            |m| matches!(m, Message::UserRemove(remove) if remove.session == carol.session_id),
            QUIET,
        )
        .await;
    assert!(sam_removed.is_none(), "superusers still see a hidden user");

    carol.trigger_context_action(ACTION_ID).await;
    bob.recv_until(
        |m| {
            matches!(m, Message::UserState(state)
                if state.session == Some(carol.session_id) && state.name.is_some())
        },
        DEADLINE,
    )
    .await
    .expect("showing carol reintroduces her to regular users");
    carol
        .recv_until(
            |m| {
                matches!(m, Message::ContextActionModify(modify)
                    if modify.action == ACTION_ID && modify.text.as_deref() == Some(HIDE_LABEL))
            },
            DEADLINE,
        )
        .await
        .expect("the toggle switches back to Hide me");
    assert!(!live_carol.is_hidden_from_regular_users());
}

const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

async fn expect_voice_from(recipient: &TestClient, sender: &TestClient, what: &str) {
    let audio = recipient
        .recv_voice_tcp(DEADLINE)
        .await
        .unwrap_or_else(|| panic!("{what}"));
    assert_eq!(audio.sender_session, Some(sender.server_session), "{what}");
}

async fn expect_no_voice(recipient: &TestClient, what: &str) {
    let audio = recipient.recv_voice_tcp(QUIET).await;
    assert!(audio.is_none(), "{what}: {audio:?}");
}

async fn move_and_wait(client: &TestClient, channel_id: u32) {
    client.move_to_channel(channel_id).await;
    expect_user_state(client, "the move should be confirmed", |state| {
        state.session == Some(client.session_id) && state.channel_id == Some(channel_id)
    })
    .await;
}

/// Checks that `promiscuous` delivers normal speech and whispers from other
/// channels exactly once, that a regular user in the same place hears none of
/// it, and that deafening still silences the promiscuous user.
#[tokio::test]
async fn promiscuous_privilege_receives_all_voice_once() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    create_channel(&server, 51, "Talk").await;
    create_channel(&server, 52, "Monitor").await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server.authenticator.register_privileged_user(
        "eve",
        None,
        Some(3),
        vec![],
        [Privilege::Promiscuous],
    );
    server
        .authenticator
        .register_user("mallory", None, Some(4), vec![]);

    let alice = connect(&server, "alice").await;
    let bob = connect(&server, "bob").await;
    let eve = connect(&server, "eve").await;
    let mallory = connect(&server, "mallory").await;
    move_and_wait(&alice, 51).await;
    move_and_wait(&bob, 51).await;
    move_and_wait(&eve, 52).await;
    move_and_wait(&mallory, 52).await;
    for client in [&alice, &bob, &eve, &mallory] {
        client.drain_now().await;
    }

    alice
        .send_voice_tcp(0, 1, Bytes::from_static(SAMPLE_OPUS))
        .await;
    expect_voice_from(&bob, &alice, "bob shares alice's channel").await;
    expect_voice_from(&eve, &alice, "eve hears speech in another channel").await;
    expect_no_voice(&mallory, "mallory has no privilege").await;

    alice
        .set_voice_target(VoiceTarget {
            id: Some(1),
            targets: vec![VoiceTargetEntry {
                session: vec![bob.session_id],
                ..Default::default()
            }],
        })
        .await;
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while live_client(&server, &alice).await.voice_target(1).is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "voice target installed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    alice
        .send_voice_tcp(1, 2, Bytes::from_static(SAMPLE_OPUS))
        .await;
    expect_voice_from(&bob, &alice, "bob is the whisper target").await;
    expect_voice_from(&eve, &alice, "eve hears whispers to others").await;
    expect_no_voice(&mallory, "mallory is not a whisper target").await;

    move_and_wait(&eve, 51).await;
    eve.drain_now().await;
    alice
        .send_voice_tcp(0, 3, Bytes::from_static(SAMPLE_OPUS))
        .await;
    expect_voice_from(&eve, &alice, "eve shares alice's channel").await;
    expect_no_voice(&eve, "a regular recipient gets no second copy").await;

    eve.set_self_deaf(true).await;
    expect_user_state(&bob, "eve's self-deaf should be observed", |state| {
        state.session == Some(eve.session_id) && state.self_deaf == Some(true)
    })
    .await;
    move_and_wait(&eve, 52).await;
    alice
        .send_voice_tcp(0, 4, Bytes::from_static(SAMPLE_OPUS))
        .await;
    expect_voice_from(&bob, &alice, "bob still hears alice").await;
    expect_no_voice(&eve, "deafening silences promiscuous delivery").await;
}

/// Checks that a promiscuous user does not hear a sender hidden from them.
#[tokio::test]
async fn promiscuous_privilege_does_not_reveal_invisible_senders() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    create_channel(&server, 51, "Talk").await;
    server.authenticator.register_privileged_user(
        "ghost",
        None,
        Some(1),
        vec![],
        [Privilege::Invisible],
    );
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server.authenticator.register_privileged_user(
        "eve",
        None,
        Some(3),
        vec![],
        [Privilege::Promiscuous],
    );

    let ghost = connect(&server, "ghost").await;
    let eve = connect(&server, "eve").await;
    let bob = connect(&server, "bob").await;
    move_and_wait(&bob, 51).await;
    move_and_wait(&eve, 51).await;
    eve.drain_now().await;

    bob.send_voice_tcp(0, 1, Bytes::from_static(SAMPLE_OPUS))
        .await;
    expect_voice_from(&eve, &bob, "eve hears a visible sender").await;

    ghost
        .send_voice_tcp(0, 2, Bytes::from_static(SAMPLE_OPUS))
        .await;
    expect_no_voice(&eve, "invisible senders stay inaudible").await;
}
