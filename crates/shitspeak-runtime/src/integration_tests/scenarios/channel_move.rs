//! Channel-move scenarios: self-move and moderator-move both produce a
//! UserState broadcast that the other client observes.

use std::time::Duration;

use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use shitspeak_messages::messages::{
    Message,
    encoder::{ChannelState, UserState},
};
use shitspeak_state::{ACL, ACLPermissions, Channel};

/// Checks that a user's own channel move is broadcast to other clients.
/// Expected: Alice receives Bob's `UserState` with the new channel id. This is
/// the Mumble `UserState.channel_id` move behavior implemented in
/// `D:\mumble\src\murmur\Messages.cpp::msgUserState` and mirrored by
/// `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn self_move_broadcasts_to_peer() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(30, "Lobby".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(30).await;

    let bob_session = bob.session_id;
    let saw = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.channel_id == Some(30))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(saw.is_some(), "Alice should see Bob's self-move to lobby");
}

/// Checks that a moderator can move another user and the target sees the move.
/// Expected: Bob receives a `UserState` placing his own session in the target
/// channel. Mumble implements this as a privileged `UserState` update in
/// `D:\mumble\src\murmur\Messages.cpp::msgUserState`; shitspeak follows the
/// same permission and broadcast path in `D:\shitspeak\message.go::handleUserStateMessage`.
#[tokio::test]
async fn moderator_move_other() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(31, "Lobby".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    let bob_session = bob.session_id;
    alice.move_other(bob_session, 31).await;

    let saw_bob = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.channel_id == Some(31))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        saw_bob.is_some(),
        "Bob should see his channel update after moderator move"
    );
}

#[tokio::test]
async fn unrelated_acl_update_preserves_temporary_visible_users_and_links() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        allow_move_without_traverse: true,
        reveal_users_in_current_and_linked_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let channels = server.server.get_channels();
    for (channel_id, name) in [
        (330, "Visible source"),
        (331, "Visible linked"),
        (332, "Unrelated ACL target"),
    ] {
        channels
            .create_channel_in_server(
                crate::types::DEFAULT_SERVER_ID,
                Channel::new(channel_id, name.to_owned(), 0, 0, Some(0)),
            )
            .await
            .unwrap();
    }
    channels
        .add_link_in_server(crate::types::DEFAULT_SERVER_ID, 330, 331)
        .await
        .unwrap();
    for channel_id in [330, 331] {
        channels
            .set_acls_in_server(
                crate::types::DEFAULT_SERVER_ID,
                channel_id,
                true,
                vec![group_acl(
                    "!mover",
                    enumflags2::BitFlags::empty(),
                    ACLPermissions::Traverse.into(),
                    false,
                )],
            )
            .await
            .unwrap();
    }

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    alice.move_other(carol.session_id, 330).await;
    carol
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(carol.session_id) && state.channel_id == Some(330))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("Carol enters the hidden source channel");
    carol
        .send(
            UserState {
                session: Some(carol.server_session),
                listening_channel_add: vec![0],
                ..Default::default()
            }
            .into(),
        )
        .await;
    carol
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(carol.session_id)
                        && state.listening_channel_add == vec![0])
            },
            Duration::from_secs(2),
        )
        .await
        .expect("Carol starts listening to the visible root channel");
    bob.drain_now().await;

    alice.move_other(bob.session_id, 330).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut saw_self = false;
    let mut saw_linked_channel = false;
    let mut saw_carol_listener = false;
    while tokio::time::Instant::now() < deadline
        && !(saw_self && saw_linked_channel && saw_carol_listener)
    {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        saw_self |= matches!(&message, Message::UserState(state)
            if state.session == Some(bob.session_id) && state.channel_id == Some(330));
        saw_linked_channel |= matches!(&message, Message::ChannelState(state)
            if state.channel_id == Some(331));
        saw_carol_listener |= matches!(&message, Message::UserState(state)
            if state.session == Some(carol.session_id)
                && state.listening_channel_add.contains(&0));
    }
    assert!(saw_self, "Bob enters the hidden source channel");
    assert!(
        saw_linked_channel,
        "Bob should receive the temporarily visible linked channel"
    );
    assert!(
        saw_carol_listener,
        "Bob should receive Carol's visible listener"
    );
    bob.drain_now().await;

    alice
        .set_acls(
            332,
            vec![shitspeak_messages::messages::encoder::ChanAcl {
                apply_here: true,
                apply_subs: false,
                inherited: false,
                user_id: None,
                group: Some("other".to_owned()),
                grant: 0,
                deny: ACLPermissions::Traverse as u32,
            }],
            true,
        )
        .await;
    alice.query_acls(332).await;
    alice
        .recv_until(
            |message| matches!(message, Message::ACL(acl) if acl.channel_id == 332),
            Duration::from_secs(2),
        )
        .await
        .expect("unrelated ACL update commits");

    assert!(
        bob.recv_until(
        |message| {
            matches!(message, Message::ChannelRemove(remove) if remove.channel_id == 331)
                || matches!(message, Message::UserRemove(remove) if remove.session == carol.session_id)
                || matches!(message, Message::UserState(state)
                    if state.session == Some(carol.session_id)
                        && state.listening_channel_remove.contains(&0))
            },
            Duration::from_millis(300),
        )
        .await
        .is_none(),
        "an unrelated ACL update must not retract temporary channels, users, or listeners"
    );
}

#[tokio::test]
async fn linked_channel_without_traverse_is_visible_from_traversable_current_channel() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        allow_move_without_traverse: true,
        reveal_users_in_current_and_linked_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let channels = server.server.get_channels();
    for (channel_id, name) in [(333, "Traversable current"), (334, "Hidden linked")] {
        channels
            .create_channel_in_server(
                crate::types::DEFAULT_SERVER_ID,
                Channel::new(channel_id, name.to_owned(), 0, 0, Some(0)),
            )
            .await
            .unwrap();
    }
    channels
        .set_acls_in_server(
            crate::types::DEFAULT_SERVER_ID,
            334,
            true,
            vec![group_acl(
                "!mover",
                enumflags2::BitFlags::empty(),
                ACLPermissions::Traverse.into(),
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
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");
    assert!(
        !bob.initial_channel_states
            .iter()
            .any(|state| state.channel_id == Some(334)),
        "Bob cannot Traverse the unlinked hidden channel"
    );

    alice.move_other(carol.session_id, 334).await;
    carol
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(carol.session_id) && state.channel_id == Some(334))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("Carol enters the hidden channel");
    bob.move_to_channel(333).await;
    bob.recv_until(
        |message| {
            matches!(message, Message::UserState(state)
                if state.session == Some(bob.session_id) && state.channel_id == Some(333))
        },
        Duration::from_secs(2),
    )
    .await
    .expect("Bob enters the traversable current channel");
    bob.drain_now().await;

    alice
        .send(
            ChannelState {
                channel_id: Some(333),
                links_add: vec![334],
                ..Default::default()
            }
            .into(),
        )
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut saw_hidden_channel = false;
    let mut saw_carol = false;
    while tokio::time::Instant::now() < deadline && !(saw_hidden_channel && saw_carol) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        saw_hidden_channel |= matches!(&message, Message::ChannelState(state)
            if state.channel_id == Some(334));
        saw_carol |= matches!(&message, Message::UserState(state)
            if state.session == Some(carol.session_id) && state.channel_id == Some(334));
    }
    assert!(
        saw_hidden_channel,
        "the linked channel should be visible from Bob's traversable current channel"
    );
    assert!(
        saw_carol,
        "users in the non-traversable linked channel should be visible"
    );
    bob.drain_now().await;

    alice
        .send(
            ChannelState {
                channel_id: Some(333),
                links_remove: vec![334],
                ..Default::default()
            }
            .into(),
        )
        .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut saw_carol_remove = false;
    let mut saw_hidden_channel_remove = false;
    while tokio::time::Instant::now() < deadline && !(saw_carol_remove && saw_hidden_channel_remove)
    {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        saw_carol_remove |= matches!(&message, Message::UserRemove(remove)
            if remove.session == carol.session_id);
        saw_hidden_channel_remove |= matches!(&message, Message::ChannelRemove(remove)
            if remove.channel_id == 334);
    }
    assert!(
        saw_carol_remove,
        "unlinking should remove users from the no-longer-visible linked channel"
    );
    assert!(
        saw_hidden_channel_remove,
        "unlinking should remove the no-longer-visible linked channel"
    );
}

const HIDDEN_PARENT: u32 = 320;
const HIDDEN_CHILD: u32 = 321;
const HIDDEN_SIBLING: u32 = 322;
const HIDDEN_LINKED: u32 = 323;

fn group_acl(
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

async fn configure_hidden_move_channels(
    server: &crate::integration_tests::harness::TestServer,
    destination_move: bool,
) {
    let channels = server.server.get_channels();
    channels
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(HIDDEN_PARENT, "Hidden parent".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();
    channels
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(
                HIDDEN_CHILD,
                "Hidden child".to_owned(),
                0,
                0,
                Some(HIDDEN_PARENT),
            ),
        )
        .await
        .unwrap();
    channels
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(
                HIDDEN_SIBLING,
                "Hidden sibling".to_owned(),
                0,
                0,
                Some(HIDDEN_PARENT),
            ),
        )
        .await
        .unwrap();
    channels
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(HIDDEN_LINKED, "Hidden linked".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();

    channels
        .set_acls_in_server(
            crate::types::DEFAULT_SERVER_ID,
            0,
            true,
            vec![group_acl(
                "mover",
                ACLPermissions::Move.into(),
                enumflags2::BitFlags::empty(),
                destination_move,
            )],
        )
        .await
        .unwrap();
    channels
        .set_acls_in_server(
            crate::types::DEFAULT_SERVER_ID,
            HIDDEN_LINKED,
            true,
            vec![group_acl(
                "!mover",
                enumflags2::BitFlags::empty(),
                (ACLPermissions::Traverse | ACLPermissions::Enter).into(),
                true,
            )],
        )
        .await
        .unwrap();
    channels
        .set_acls_in_server(
            crate::types::DEFAULT_SERVER_ID,
            HIDDEN_PARENT,
            true,
            vec![group_acl(
                "!mover",
                enumflags2::BitFlags::empty(),
                (ACLPermissions::Traverse | ACLPermissions::Enter).into(),
                true,
            )],
        )
        .await
        .unwrap();
}

async fn connect_hidden_move_clients(
    server: &crate::integration_tests::harness::TestServer,
) -> (TestClient, TestClient) {
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["mover".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(server, "bob", None)
        .await
        .expect("bob");
    assert!(
        [HIDDEN_PARENT, HIDDEN_CHILD, HIDDEN_SIBLING, HIDDEN_LINKED]
            .into_iter()
            .all(|channel_id| !bob
                .initial_channel_states
                .iter()
                .any(|state| state.channel_id == Some(channel_id))),
        "Bob's initial sync must omit the entire hidden subtree"
    );
    alice.drain_now().await;
    bob.drain_now().await;

    // `ServerSync` reaches the socket before the connection task transfers its
    // visibility baseline to a projection shard.  A projected self update is
    // the readiness barrier: once it arrives, subsequent visibility changes
    // are rendered by the same shard rather than racing its registration.
    bob.set_self_mute(true).await;
    let projection_ready = bob
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(bob.session_id) && state.self_mute == Some(true))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        projection_ready.is_some(),
        "Bob's projection must be ready before exercising hidden-channel visibility"
    );
    alice.drain_now().await;
    bob.drain_now().await;
    (alice, bob)
}

#[tokio::test]
async fn moderator_move_without_target_traverse_is_denied_by_default() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    configure_hidden_move_channels(&server, true).await;
    let (alice, bob) = connect_hidden_move_clients(&server).await;

    alice.move_other(bob.session_id, HIDDEN_CHILD).await;

    let denied = alice
        .recv_until(
            |message| {
                matches!(message, Message::PermissionDenied(denied)
                    if denied.session == Some(bob.session_id)
                        && denied.channel_id == Some(HIDDEN_CHILD)
                        && denied.permission == Some(ACLPermissions::Traverse as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(denied.is_some(), "default policy must deny the hidden move");
    let live_bob = server
        .server
        .get_clients()
        .get_client_in_server(crate::types::DEFAULT_SERVER_ID, bob.server_session)
        .await
        .expect("Bob remains connected");
    assert_eq!(
        live_bob.get_current_channel_id(),
        0,
        "a denied move must not mutate Bob's authoritative channel"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        assert!(
            !matches!(&message, Message::UserState(state)
                if state.session == Some(bob.session_id)
                    && state.channel_id == Some(HIDDEN_CHILD)),
            "Bob must remain in the source channel after denial"
        );
        assert!(
            !matches!(&message, Message::ChannelState(state)
                if matches!(state.channel_id, Some(HIDDEN_PARENT | HIDDEN_CHILD | HIDDEN_SIBLING))),
            "a denied move must not reveal hidden channels"
        );
    }
}

#[tokio::test]
async fn allowed_hidden_move_reveals_hierarchy_before_move_and_revokes_after_leave() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        allow_move_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    configure_hidden_move_channels(&server, true).await;
    let (alice, bob) = connect_hidden_move_clients(&server).await;

    alice.move_other(bob.session_id, HIDDEN_CHILD).await;

    let mut relevant = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        let is_move = matches!(&message, Message::UserState(state)
            if state.session == Some(bob.session_id)
                && state.channel_id == Some(HIDDEN_CHILD));
        if matches!(&message, Message::ChannelState(state)
                if matches!(state.channel_id, Some(HIDDEN_PARENT | HIDDEN_CHILD | HIDDEN_SIBLING)))
            || matches!(&message, Message::PermissionQuery(query)
                if matches!(query.channel_id, Some(HIDDEN_PARENT | HIDDEN_CHILD | HIDDEN_SIBLING)))
            || is_move
        {
            relevant.push(message);
        }
        if is_move {
            break;
        }
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    relevant.extend(bob.drain_now().await.into_iter().filter(|message| {
        matches!(message, Message::ChannelState(state)
            if matches!(state.channel_id, Some(HIDDEN_PARENT | HIDDEN_CHILD | HIDDEN_SIBLING)))
            || matches!(message, Message::PermissionQuery(query)
                if matches!(query.channel_id, Some(HIDDEN_PARENT | HIDDEN_CHILD | HIDDEN_SIBLING)))
            || matches!(message, Message::UserState(state)
                if state.session == Some(bob.session_id)
                    && state.channel_id == Some(HIDDEN_CHILD))
    }));

    assert!(
        relevant.iter().all(|message| !matches!(message,
            Message::ChannelState(state) if state.channel_id == Some(HIDDEN_SIBLING)
        ) && !matches!(message,
            Message::PermissionQuery(query) if query.channel_id == Some(HIDDEN_SIBLING))),
        "temporary visibility must not disclose a hidden sibling"
    );
    let parent_state = relevant.iter().find_map(|message| match message {
        Message::ChannelState(state) if state.channel_id == Some(HIDDEN_PARENT) => Some(state),
        _ => None,
    });
    let child_state = relevant.iter().find_map(|message| match message {
        Message::ChannelState(state) if state.channel_id == Some(HIDDEN_CHILD) => Some(state),
        _ => None,
    });
    assert_eq!(
        parent_state.and_then(|state| state.parent),
        Some(0),
        "unexpected temporary channel-state sequence: {relevant:?}"
    );
    assert_eq!(
        child_state.and_then(|state| state.parent),
        Some(HIDDEN_PARENT)
    );
    let sequence = relevant
        .iter()
        .filter_map(|message| match message {
            Message::ChannelState(state) if state.channel_id == Some(HIDDEN_PARENT) => {
                Some("parent-state")
            }
            Message::ChannelState(state) if state.channel_id == Some(HIDDEN_CHILD) => {
                Some("child-state")
            }
            Message::PermissionQuery(query) if query.channel_id == Some(HIDDEN_CHILD) => {
                Some("child-permissions")
            }
            Message::PermissionQuery(query) if query.channel_id == Some(HIDDEN_PARENT) => {
                Some("parent-permissions")
            }
            Message::UserState(state)
                if state.session == Some(bob.session_id)
                    && state.channel_id == Some(HIDDEN_CHILD) =>
            {
                Some("self-move")
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        sequence,
        vec![
            "parent-state",
            "child-state",
            "child-permissions",
            "parent-permissions",
            "self-move",
        ],
        "the hierarchy and its permission references must precede the move"
    );

    bob.drain_now().await;
    alice.move_other(bob.session_id, 0).await;
    let mut leave_sequence = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline && leave_sequence.len() < 3 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        match message {
            Message::UserState(state)
                if state.session == Some(bob.session_id) && state.channel_id == Some(0) =>
            {
                leave_sequence.push("self-move")
            }
            Message::ChannelRemove(remove) if remove.channel_id == HIDDEN_CHILD => {
                leave_sequence.push("child-remove")
            }
            Message::ChannelRemove(remove) if remove.channel_id == HIDDEN_PARENT => {
                leave_sequence.push("parent-remove")
            }
            Message::ChannelRemove(remove) if remove.channel_id == HIDDEN_SIBLING => {
                panic!("hidden sibling was never visible and must not be removed")
            }
            _ => {}
        }
    }
    assert_eq!(
        leave_sequence,
        vec!["self-move", "child-remove", "parent-remove"],
        "departure must be delivered before descendant-first visibility revocation"
    );
}

#[tokio::test]
async fn allowed_hidden_move_keeps_users_and_links_hidden_without_opt_in() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        allow_move_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    configure_hidden_move_channels(&server, true).await;
    server
        .server
        .get_channels()
        .add_link_in_server(crate::types::DEFAULT_SERVER_ID, HIDDEN_CHILD, HIDDEN_LINKED)
        .await
        .expect("link hidden channels");
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);
    server
        .authenticator
        .register_user("dave", None, Some(4), vec![]);

    let (alice, bob) = connect_hidden_move_clients(&server).await;
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");
    let dave = TestClient::connect_and_authenticate(&server, "dave", None)
        .await
        .expect("dave");
    alice.move_other(carol.session_id, HIDDEN_CHILD).await;
    carol
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(carol.session_id)
                        && state.channel_id == Some(HIDDEN_CHILD))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("Carol enters the hidden current channel");
    alice.move_other(dave.session_id, HIDDEN_LINKED).await;
    dave.recv_until(
        |message| {
            matches!(message, Message::UserState(state)
                    if state.session == Some(dave.session_id)
                        && state.channel_id == Some(HIDDEN_LINKED))
        },
        Duration::from_secs(2),
    )
    .await
    .expect("Dave enters the hidden linked channel");
    bob.drain_now().await;

    alice.move_other(bob.session_id, HIDDEN_CHILD).await;
    bob.recv_until(
        |message| {
            matches!(message, Message::UserState(state)
                    if state.session == Some(bob.session_id)
                        && state.channel_id == Some(HIDDEN_CHILD))
        },
        Duration::from_secs(2),
    )
    .await
    .expect("Bob enters the hidden current channel");

    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        assert!(
            !matches!(&message, Message::ChannelState(state)
                if state.channel_id == Some(HIDDEN_LINKED))
                && !matches!(&message, Message::UserState(state)
                    if matches!(state.session, Some(session)
                        if session == carol.session_id || session == dave.session_id)),
            "the default policy must not reveal hidden linked channels or their users"
        );
    }
}

#[tokio::test]
async fn allowed_hidden_move_reveals_current_and_linked_channel_users_when_configured() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        allow_move_without_traverse: true,
        reveal_users_in_current_and_linked_channels_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    configure_hidden_move_channels(&server, true).await;
    server
        .server
        .get_channels()
        .add_link_in_server(crate::types::DEFAULT_SERVER_ID, HIDDEN_CHILD, HIDDEN_LINKED)
        .await
        .expect("link hidden channels");
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);
    server
        .authenticator
        .register_user("dave", None, Some(4), vec![]);

    let (alice, bob) = connect_hidden_move_clients(&server).await;
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");
    let dave = TestClient::connect_and_authenticate(&server, "dave", None)
        .await
        .expect("dave");

    alice.move_other(carol.session_id, HIDDEN_CHILD).await;
    carol
        .recv_until(
            |message| {
                matches!(message, Message::UserState(state)
                    if state.session == Some(carol.session_id)
                        && state.channel_id == Some(HIDDEN_CHILD))
            },
            Duration::from_secs(2),
        )
        .await
        .expect("Carol enters the hidden current channel");
    alice.move_other(dave.session_id, HIDDEN_LINKED).await;
    dave.recv_until(
        |message| {
            matches!(message, Message::UserState(state)
                    if state.session == Some(dave.session_id)
                        && state.channel_id == Some(HIDDEN_LINKED))
        },
        Duration::from_secs(2),
    )
    .await
    .expect("Dave enters the hidden linked channel");
    bob.drain_now().await;

    alice.move_other(bob.session_id, HIDDEN_CHILD).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut relevant = Vec::new();
    let mut saw_child = false;
    let mut saw_linked = false;
    let mut saw_carol = false;
    let mut saw_dave = false;
    while tokio::time::Instant::now() < deadline
        && !(saw_child && saw_linked && saw_carol && saw_dave)
    {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        saw_child |= matches!(&message, Message::ChannelState(state)
            if state.channel_id == Some(HIDDEN_CHILD));
        saw_linked |= matches!(&message, Message::ChannelState(state)
            if state.channel_id == Some(HIDDEN_LINKED));
        saw_carol |= matches!(&message, Message::UserState(state)
            if state.session == Some(carol.session_id) && state.channel_id == Some(HIDDEN_CHILD));
        saw_dave |= matches!(&message, Message::UserState(state)
            if state.session == Some(dave.session_id) && state.channel_id == Some(HIDDEN_LINKED));
        if matches!(&message, Message::ChannelState(state)
            if state.channel_id == Some(HIDDEN_SIBLING))
        {
            panic!("temporary visibility must not disclose a hidden sibling");
        }
        relevant.push(message);
    }

    assert!(saw_child, "Bob should receive his hidden current channel");
    assert!(
        saw_linked,
        "Bob should receive the directly linked hidden channel"
    );
    assert!(
        saw_carol,
        "Bob should see users in his hidden current channel"
    );
    assert!(
        saw_dave,
        "Bob should see users in the directly linked hidden channel"
    );

    let last_channel_index = relevant
        .iter()
        .rposition(|message| {
            matches!(message, Message::ChannelState(state)
                if matches!(state.channel_id, Some(HIDDEN_CHILD | HIDDEN_LINKED)))
        })
        .expect("relevant channel states");
    let first_peer_index = relevant
        .iter()
        .position(|message| {
            matches!(message, Message::UserState(state)
                if matches!(state.session, Some(session)
                    if session == carol.session_id || session == dave.session_id))
        })
        .expect("relevant peer state");
    assert!(
        last_channel_index < first_peer_index,
        "temporary channels must be introduced before their users: {relevant:?}"
    );
}

#[tokio::test]
async fn allowed_hidden_move_still_requires_destination_move_when_target_cannot_enter() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        allow_move_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    configure_hidden_move_channels(&server, false).await;
    let (alice, bob) = connect_hidden_move_clients(&server).await;

    alice.move_other(bob.session_id, HIDDEN_CHILD).await;

    let denied = alice
        .recv_until(
            |message| {
                matches!(message, Message::PermissionDenied(denied)
                    if denied.session == Some(alice.session_id)
                        && denied.channel_id == Some(HIDDEN_CHILD)
                        && denied.permission == Some(ACLPermissions::Move as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        denied.is_some(),
        "allowing hidden moves must not bypass destination Move"
    );
    let live_bob = server
        .server
        .get_clients()
        .get_client_in_server(crate::types::DEFAULT_SERVER_ID, bob.server_session)
        .await
        .expect("Bob remains connected");
    assert_eq!(
        live_bob.get_current_channel_id(),
        0,
        "missing destination Move must leave Bob in the source channel"
    );
    assert!(
        bob.recv_until(
            |message| matches!(message, Message::UserState(state)
                if state.session == Some(bob.session_id)
                    && state.channel_id == Some(HIDDEN_CHILD)),
            Duration::from_millis(300),
        )
        .await
        .is_none(),
        "Bob must remain in the source channel when destination Move is missing"
    );
}

#[tokio::test]
async fn rapid_hidden_move_then_leave_keeps_each_transition_ordered() {
    let server = spawn_test_server(TestServerOpts {
        hide_users_without_traverse: true,
        hide_channels_without_traverse: true,
        allow_move_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    configure_hidden_move_channels(&server, true).await;
    let (alice, bob) = connect_hidden_move_clients(&server).await;

    alice.move_other(bob.session_id, HIDDEN_CHILD).await;
    alice.move_other(bob.session_id, 0).await;

    let mut sequence = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline && sequence.len() < 9 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(message) = bob.recv(remaining).await else {
            break;
        };
        match message {
            Message::ChannelState(state) if state.channel_id == Some(HIDDEN_PARENT) => {
                sequence.push("parent-state")
            }
            Message::ChannelState(state) if state.channel_id == Some(HIDDEN_CHILD) => {
                sequence.push("child-state")
            }
            Message::PermissionQuery(query) if query.channel_id == Some(HIDDEN_CHILD) => {
                sequence.push("child-permissions")
            }
            Message::PermissionQuery(query) if query.channel_id == Some(HIDDEN_PARENT) => {
                sequence.push("parent-permissions")
            }
            Message::UserState(state)
                if state.session == Some(bob.session_id)
                    && state.channel_id == Some(HIDDEN_CHILD) =>
            {
                sequence.push("hidden-move")
            }
            Message::PermissionQuery(query) if query.channel_id == Some(0) => {
                sequence.push("root-permissions")
            }
            Message::UserState(state)
                if state.session == Some(bob.session_id) && state.channel_id == Some(0) =>
            {
                sequence.push("root-move")
            }
            Message::ChannelRemove(remove) if remove.channel_id == HIDDEN_CHILD => {
                sequence.push("child-remove")
            }
            Message::ChannelRemove(remove) if remove.channel_id == HIDDEN_PARENT => {
                sequence.push("parent-remove")
            }
            Message::ChannelState(state) if state.channel_id == Some(HIDDEN_SIBLING) => {
                panic!("rapid moves must not reveal the hidden sibling")
            }
            Message::PermissionQuery(query) if query.channel_id == Some(HIDDEN_SIBLING) => {
                panic!("rapid moves must not reference the hidden sibling")
            }
            Message::ChannelRemove(remove) if remove.channel_id == HIDDEN_SIBLING => {
                panic!("an undisclosed sibling must not be removed")
            }
            _ => {}
        }
    }

    assert_eq!(
        sequence,
        vec![
            "parent-state",
            "child-state",
            "child-permissions",
            "parent-permissions",
            "hidden-move",
            "root-permissions",
            "root-move",
            "child-remove",
            "parent-remove",
        ],
        "back-to-back moves must project using each log entry's destination"
    );
}
