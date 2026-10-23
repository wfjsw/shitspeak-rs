//! Regression tests for channel-listener ("listen to") semantics.
//!
//! A listener of channel X must be treated as if they were sitting in X for
//! every *delivery* decision: normal speech that reaches X (including speech
//! that arrives over a channel link) and channel/tree text addressed to X.
//!
//! These encode three reported symptoms:
//! 1. a listener of a *linked* channel hears normal speech from the link group,
//! 2. linked-channel normal speech works under a shared `@~sub,-1` Speak ACL,
//! 3. co-present members of a channel receive that channel's text messages.

use std::time::Duration;

use bytes::Bytes;

use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use shitspeak_messages::messages::Message;
use shitspeak_messages::messages::encoder::{ChanAcl, TextMessage, UserState};
use shitspeak_state::{ACLPermissions, Channel};

const VOICE_DEADLINE: Duration = Duration::from_secs(2);
const NEGATIVE_WINDOW: Duration = Duration::from_millis(500);
const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

fn opus_frame(payload: &crate::voice::codec::AudioPayload) -> &[u8] {
    match payload {
        crate::voice::codec::AudioPayload::Opus(p) => &p.frame,
        _ => panic!("expected Opus payload, got {payload:?}"),
    }
}

async fn expect_voice_from(recipient: &TestClient, sender: &TestClient, reason: &str) {
    let audio = recipient
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect(reason);
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(sender.server_session));
}

async fn expect_user_channel(client: &TestClient, channel_id: u32, reason: &str) {
    client
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(client.session_id) && us.channel_id == Some(channel_id))
            },
            VOICE_DEADLINE,
        )
        .await
        .expect(reason);
}

async fn listen_to_channel(listener: &TestClient, channel_id: u32, reason: &str) {
    listener
        .send(
            UserState {
                session: Some(listener.server_session),
                listening_channel_add: vec![channel_id],
                ..Default::default()
            }
            .into(),
        )
        .await;
    listener
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(listener.session_id)
                        && us.listening_channel_add.contains(&channel_id))
            },
            VOICE_DEADLINE,
        )
        .await
        .expect(reason);
    listener.drain_now().await;
}

async fn expect_channel_text(
    recipient: &TestClient,
    expected: &str,
    channel_id: u32,
    reason: &str,
) -> Message {
    recipient
        .recv_until(
            |m| {
                matches!(m, Message::TextMessage(t)
                    if t.message == expected
                        && t.channel_id.contains(&channel_id))
            },
            VOICE_DEADLINE,
        )
        .await
        .unwrap_or_else(|| panic!("{reason}"))
}

/// Like [`expect_channel_text`], but for a message addressed to a channel
/// *subtree*. Those carry the root in `tree_id` and leave `channel_id` empty.
async fn expect_tree_text(recipient: &TestClient, expected: &str, root: u32, reason: &str) -> Message {
    recipient
        .recv_until(
            |m| {
                matches!(m, Message::TextMessage(t)
                    if t.message == expected
                        && t.tree_id.contains(&root)
                        && t.channel_id.is_empty())
            },
            VOICE_DEADLINE,
        )
        .await
        .unwrap_or_else(|| panic!("{reason}"))
}

/// A listener of a LINKED channel must hear normal speech coming from the
/// other member of the link group, exactly as a member of that channel does.
#[tokio::test]
async fn listener_of_linked_channel_hears_normal_voice() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(218, "Source".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(72, "Linked".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();
    chans
        .add_link_in_server(crate::types::DEFAULT_SERVER_ID, 218, 72)
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

    bob.move_to_channel(72).await;
    listen_to_channel(&carol, 72, "Carol listens to the linked channel").await;
    expect_user_channel(&bob, 72, "Bob enters the linked channel").await;
    bob.drain_now().await;

    alice.move_to_channel(218).await;
    expect_user_channel(&alice, 218, "Alice enters the source channel").await;
    alice.drain_now().await;

    alice
        .send_voice_tcp(0, 5, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "member of the linked channel hears normal speech over the link",
    )
    .await;
    expect_voice_from(
        &carol,
        &alice,
        "listener of the linked channel must hear exactly what a member hears",
    )
    .await;
}

/// A listener of the SOURCE channel hears normal speech (control for the
/// linked-channel case above — this path already works).
#[tokio::test]
async fn listener_of_source_channel_hears_normal_voice() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(218, "Source".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    listen_to_channel(&carol, 218, "Carol listens to the source channel").await;

    alice
        .send_voice_tcp(0, 5, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(&carol, &alice, "listener of the source channel hears").await;
}

/// Linked-channel normal speech must work for a non-superuser speaker whose
/// Speak on the linked channel comes from a shared `@~sub,-1` ACL, not from
/// the default grant.
#[tokio::test]
async fn linked_normal_voice_under_shared_sub_acl() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("admin", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("alice", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    // Root -> parent(300) -> {273, 275} : the two channels share one ACL
    // hierarchy and are linked to each other.
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(300, "Parent".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(273, "A".to_owned(), 0, 0, Some(300)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(275, "B".to_owned(), 0, 0, Some(300)),
        )
        .await
        .unwrap();
    chans
        .add_link_in_server(crate::types::DEFAULT_SERVER_ID, 273, 275)
        .await
        .unwrap();

    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    // Same ACL on both channels: strip the default Speak grant and re-add it
    // through the shared `~sub,-1` group.
    let shared_acl = vec![
        ChanAcl {
            apply_here: true,
            apply_subs: true,
            inherited: false,
            user_id: None,
            group: Some("all".into()),
            grant: 0,
            deny: ACLPermissions::Speak as u32,
        },
        ChanAcl {
            apply_here: true,
            apply_subs: true,
            inherited: false,
            user_id: None,
            group: Some("~sub,-1".into()),
            grant: ACLPermissions::Speak as u32,
            deny: 0,
        },
    ];
    admin
        .set_acls(
            300,
            shared_acl.clone(),
            true,
        )
        .await;
    admin.set_acls(273, shared_acl.clone(), true).await;
    admin.set_acls(275, shared_acl, true).await;

    alice.move_to_channel(273).await;
    bob.move_to_channel(275).await;
    expect_user_channel(&alice, 273, "Alice enters 273").await;
    expect_user_channel(&bob, 275, "Bob enters 275").await;
    bob.drain_now().await;

    let alice_server = server
        .server
        .get_clients()
        .get_client_in_server(crate::types::DEFAULT_SERVER_ID, alice.server_session)
        .await
        .expect("alice is connected");
    let source_perms =
        crate::client::acl::compute_permissions_for_client(&server.server, &alice_server, 273).await;
    let linked_perms =
        crate::client::acl::compute_permissions_for_client(&server.server, &alice_server, 275).await;
    assert!(
        source_perms.contains(ACLPermissions::Speak),
        "Alice must hold Speak in her own channel 273"
    );
    assert!(
        linked_perms.contains(ACLPermissions::Speak),
        "Alice must hold Speak in linked channel 275 via the shared @~sub,-1 ACL \
         (got {linked_perms:?}); linked voice is gated on this"
    );

    alice
        .send_voice_tcp(0, 7, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "co-present linked-channel listener hears normal speech under the shared ACL",
    )
    .await;
}

/// Two ordinary co-present members: a channel text addressed to their channel
/// must be delivered.
#[tokio::test]
async fn same_channel_text_reaches_co_present_member() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(273, "Room".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.move_to_channel(273).await;
    bob.move_to_channel(273).await;
    expect_user_channel(&alice, 273, "Alice enters 273").await;
    expect_user_channel(&bob, 273, "Bob enters 273").await;
    bob.drain_now().await;

    alice
        .send(
            TextMessage {
                actor: None,
                session: Vec::new(),
                channel_id: vec![273],
                tree_id: Vec::new(),
                message: "hello in channel".to_owned(),
            }
            .into(),
        )
        .await;

    expect_channel_text(
        &bob,
        "hello in channel",
        273,
        "co-present member must receive the channel text",
    )
    .await;
}

/// A listener of a channel must receive that channel's text messages, exactly
/// as a member of the channel would.
#[tokio::test]
async fn listener_of_channel_receives_channel_text() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(273, "Room".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.move_to_channel(273).await;
    expect_user_channel(&alice, 273, "Alice enters 273").await;
    listen_to_channel(&bob, 273, "Bob listens to 273 from elsewhere").await;

    alice
        .send(
            TextMessage {
                actor: None,
                session: Vec::new(),
                channel_id: vec![273],
                tree_id: Vec::new(),
                message: "hello listener".to_owned(),
            }
            .into(),
        )
        .await;

    expect_channel_text(
        &bob,
        "hello listener",
        273,
        "listener of the channel must receive the channel text",
    )
    .await;
}

/// Tree text covering a channel must also reach that channel's listeners.
#[tokio::test]
async fn listener_of_channel_receives_tree_text() {
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
            Channel::new(300, "Parent".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(273, "Child".to_owned(), 0, 0, Some(300)),
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.move_to_channel(300).await;
    expect_user_channel(&alice, 300, "Alice enters the tree root").await;
    listen_to_channel(&bob, 273, "Bob listens to the child channel").await;

    alice
        .send(
            TextMessage {
                actor: None,
                session: Vec::new(),
                channel_id: Vec::new(),
                tree_id: vec![300],
                message: "hello subtree".to_owned(),
            }
            .into(),
        )
        .await;

    expect_tree_text(
        &bob,
        "hello subtree",
        300,
        "listener of a subtree channel must receive the tree text",
    )
    .await;
}

/// Control: an unrelated listener must not receive someone else's channel text.
#[tokio::test]
async fn listener_of_unrelated_channel_does_not_receive_channel_text() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(273, "Room".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(275, "Other".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    alice.move_to_channel(273).await;
    expect_user_channel(&alice, 273, "Alice enters 273").await;
    listen_to_channel(&bob, 275, "Bob listens to an unrelated channel").await;

    alice
        .send(
            TextMessage {
                actor: None,
                session: Vec::new(),
                channel_id: vec![273],
                tree_id: Vec::new(),
                message: "not for bob".to_owned(),
            }
            .into(),
        )
        .await;

    let leaked = bob
        .recv_until(
            |m| matches!(m, Message::TextMessage(t) if t.message == "not for bob"),
            NEGATIVE_WINDOW,
        )
        .await;
    assert!(
        leaked.is_none(),
        "listener of an unrelated channel must not receive 273's text"
    );
}/// Reproduces the production ACL shape on the 273 subtree: root denies
/// Traverse for `all` on subs, the intermediate `Alliances` channel grants
/// Traverse to `member`/`highsec` with `apply_subs=false`, and only the
/// destination channels carry Enter/Speak/Listen/TextMessage grants.
///
/// The ancestor Traverse path gate must not wipe the destination's own
/// grants for a user who is already sitting in the channel.
#[tokio::test]
async fn destination_grants_survive_traverse_path_gate_for_occupant() {
    // Production runs with `allow_move_without_traverse = true`, which is what
    // lets a moderator park a client into a subtree it cannot reach on its own.
    let server = spawn_test_server(TestServerOpts {
        allow_move_without_traverse: true,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("admin", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bot", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("stranger", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(118, "Alliances".to_owned(), 0, 0, Some(0)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(119, "FRT".to_owned(), 0, 0, Some(118)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(211, "Meeting".to_owned(), 0, 0, Some(119)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(273, "Host".to_owned(), 0, 0, Some(211)),
        )
        .await
        .unwrap();
    chans
        .create_channel_in_server(
            crate::types::DEFAULT_SERVER_ID,
            Channel::new(275, "Listen-Only".to_owned(), 0, 0, Some(211)),
        )
        .await
        .unwrap();
    chans
        .add_link_in_server(crate::types::DEFAULT_SERVER_ID, 273, 275)
        .await
        .unwrap();

    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let bot = TestClient::connect_and_authenticate(&server, "bot", None)
        .await
        .expect("bot");
    let stranger = TestClient::connect_and_authenticate(&server, "stranger", None)
        .await
        .expect("stranger");

    let traverse_enter_speak_listen = (ACLPermissions::Traverse
        | ACLPermissions::Enter
        | ACLPermissions::Speak
        | ACLPermissions::Listen)
        .bits();

    admin
        .set_acls(
            0,
            vec![
                ChanAcl {
                    apply_here: true,
                    apply_subs: true,
                    inherited: false,
                    user_id: None,
                    group: Some("all".into()),
                    grant: 0,
                    deny: traverse_enter_speak_listen,
                },
                ChanAcl {
                    apply_here: true,
                    apply_subs: false,
                    inherited: false,
                    user_id: None,
                    group: Some("all".into()),
                    grant: ACLPermissions::Traverse as u32,
                    deny: 0,
                },
            ],
            true,
        )
        .await;
    admin
        .set_acls(
            118,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: false,
                inherited: false,
                user_id: None,
                group: Some("member".into()),
                grant: ACLPermissions::Traverse as u32,
                deny: 0,
            }],
            true,
        )
        .await;
    admin
        .set_acls(
            273,
            vec![
                ChanAcl {
                    apply_here: true,
                    apply_subs: true,
                    inherited: false,
                    user_id: None,
                    group: Some("all".into()),
                    grant: (ACLPermissions::Enter
                        | ACLPermissions::Speak
                        | ACLPermissions::Listen
                        | ACLPermissions::TextMessage)
                        .bits(),
                    deny: 0,
                },
                ChanAcl {
                    apply_here: true,
                    apply_subs: true,
                    inherited: false,
                    user_id: None,
                    group: Some("~sub,-1".into()),
                    grant: ACLPermissions::Speak as u32,
                    deny: 0,
                },
            ],
            true,
        )
        .await;
    admin
        .set_acls(
            275,
            vec![
                ChanAcl {
                    apply_here: true,
                    apply_subs: true,
                    inherited: false,
                    user_id: None,
                    group: Some("all".into()),
                    grant: (ACLPermissions::Enter | ACLPermissions::Listen).bits(),
                    deny: 0,
                },
                ChanAcl {
                    apply_here: true,
                    apply_subs: true,
                    inherited: false,
                    user_id: None,
                    group: Some("~sub,-1".into()),
                    grant: ACLPermissions::Speak as u32,
                    deny: 0,
                },
            ],
            true,
        )
        .await;

    admin.move_other(bot.session_id, 273).await;
    expect_user_channel(&bot, 273, "bot enters 273").await;

    let bot_server = server
        .server
        .get_clients()
        .get_client_in_server(crate::types::DEFAULT_SERVER_ID, bot.server_session)
        .await
        .expect("bot is connected");

    let as_if_in = crate::client::acl::compute_permissions_for_client_as_if_in_channel(
        &server.server,
        &bot_server,
        273,
    )
    .await;
    assert!(
        as_if_in.contains(ACLPermissions::Speak),
        "destination Speak grant must survive the ancestor Traverse path gate \
         for an occupant of 273 (got {as_if_in:?}); this is what suppresses the bot on entry"
    );
    assert!(
        as_if_in.contains(ACLPermissions::TextMessage),
        "destination TextMessage grant must survive the ancestor Traverse path gate \
         (got {as_if_in:?}); this is what rejects the bot's replies"
    );

    let linked =
        crate::client::acl::compute_permissions_for_client(&server.server, &bot_server, 275).await;
    assert!(
        linked.contains(ACLPermissions::Speak),
        "@~sub,-1 Speak on linked channel 275 must survive the ancestor Traverse path gate \
         (got {linked:?}); this is what blocks linked-channel voice"
    );

    bot.send(
        TextMessage {
            actor: None,
            session: Vec::new(),
            channel_id: vec![273],
            tree_id: Vec::new(),
            message: "bot reply".to_owned(),
        }
        .into(),
    )
    .await;
    let denied = bot
        .recv_until(|m| matches!(m, Message::PermissionDenied(_)), NEGATIVE_WINDOW)
        .await;
    assert!(
        denied.is_none(),
        "an occupant of 273 must not be denied TextMessage on 273"
    );

    // ── The barrier itself is unchanged for everyone else ──────────────────
    // `stranger` sits in root, which is neither 273 nor linked to it, so the
    // ancestor Traverse barrier still applies in full.
    let stranger_server = server
        .server
        .get_clients()
        .get_client_in_server(crate::types::DEFAULT_SERVER_ID, stranger.server_session)
        .await
        .expect("stranger is connected");
    assert_eq!(
        stranger_server.get_current_channel_id(),
        0,
        "stranger must not have been moved into the subtree"
    );

    let stranger_view = crate::client::acl::compute_permissions_for_client(
        &server.server,
        &stranger_server,
        273,
    )
    .await;
    assert!(
        stranger_view.is_empty(),
        "the ancestor Traverse barrier must still wipe 273's grants for a client \
         who cannot reach it (got {stranger_view:?})"
    );

    stranger
        .send(
            TextMessage {
                actor: None,
                session: Vec::new(),
                channel_id: vec![273],
                tree_id: Vec::new(),
                message: "should not arrive".to_owned(),
            }
            .into(),
        )
        .await;
    let stranger_denied = stranger
        .recv_until(
            |m| matches!(m, Message::PermissionDenied(_)),
            VOICE_DEADLINE,
        )
        .await;
    assert!(
        stranger_denied.is_some(),
        "a client who cannot reach 273 must still be denied TextMessage there"
    );
}