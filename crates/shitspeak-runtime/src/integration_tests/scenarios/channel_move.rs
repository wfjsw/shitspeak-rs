//! Channel-move scenarios: self-move and moderator-move both produce a
//! UserState broadcast that the other client observes.

use std::time::Duration;

use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use shitspeak_messages::messages::Message;
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
        .create_channel(Channel::new(30, "Lobby".to_owned(), 0, 0, Some(0)))
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
        .create_channel(Channel::new(31, "Lobby".to_owned(), 0, 0, Some(0)))
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

const HIDDEN_PARENT: u32 = 320;
const HIDDEN_CHILD: u32 = 321;
const HIDDEN_SIBLING: u32 = 322;

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
        .create_channel(Channel::new(
            HIDDEN_PARENT,
            "Hidden parent".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    channels
        .create_channel(Channel::new(
            HIDDEN_CHILD,
            "Hidden child".to_owned(),
            0,
            0,
            Some(HIDDEN_PARENT),
        ))
        .await
        .unwrap();
    channels
        .create_channel(Channel::new(
            HIDDEN_SIBLING,
            "Hidden sibling".to_owned(),
            0,
            0,
            Some(HIDDEN_PARENT),
        ))
        .await
        .unwrap();

    channels
        .set_acls(
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
        .set_acls(
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
        [HIDDEN_PARENT, HIDDEN_CHILD, HIDDEN_SIBLING]
            .into_iter()
            .all(|channel_id| !bob
                .initial_channel_states
                .iter()
                .any(|state| state.channel_id == Some(channel_id))),
        "Bob's initial sync must omit the entire hidden subtree"
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
        .get_client(bob.server_session)
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
    assert_eq!(parent_state.and_then(|state| state.parent), Some(0));
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
        .get_client(bob.server_session)
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
