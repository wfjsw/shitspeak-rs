//! Localization flows: channel-name translation from Weblate, live updates of
//! server text, and language changes of connected clients.

use std::time::Duration;

use shitspeak_messages::messages::Message;
use shitspeak_messages::messages::encoder::RejectType;
use shitspeak_runtime_config::{
    ChannelNameTranslationConfig, TranslationSyncConfig, WeblateComponentConfig,
};

use crate::integration_tests::harness::test_client::ConnectError;
use crate::integration_tests::harness::{TestClient, TestServer, TestServerOpts, spawn_test_server};
use crate::localization::Language;
use crate::localization::weblate_mock::MockWeblate;
use crate::types::DEFAULT_SERVER_ID;

const SOURCE: &str = "x_channel";
const WAIT: Duration = Duration::from_secs(5);

fn language(tag: &str) -> Language {
    Language::parse(tag).expect("valid language tag")
}

fn channel_names_config(mock: &MockWeblate) -> ChannelNameTranslationConfig {
    ChannelNameTranslationConfig::new(WeblateComponentConfig::new(
        mock.url(),
        "shitspeak",
        "channel-names",
        Some("wlu_token".to_owned()),
    ))
    .with_poll_interval(Duration::from_secs(1))
}

/// A component with the custom source language holding the raw names, and a
/// Spanish translation.
async fn channel_name_component() -> MockWeblate {
    let mock = MockWeblate::start().await;
    mock.set_translation(SOURCE, true, &[("Root", "Root"), ("Lobby", "Lobby")]);
    mock.set_translation("es", false, &[("Root", "Raíz"), ("Lobby", "Vestíbulo")]);
    mock
}

async fn server_with_channel_names(mock: &MockWeblate) -> TestServer {
    let server = spawn_test_server(TestServerOpts {
        channel_name_translation: Some(channel_names_config(mock)),
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("admin", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user_with_language("carmen", None, Some(2), vec![], language("es-MX"));
    server
        .authenticator
        .register_user_with_language("hans", None, Some(3), vec![], language("de"));
    server
}

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    tokio::time::timeout(WAIT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

async fn wait_for_translation(server: &TestServer, tag: &str, raw: &str, translated: &str) {
    let translations = server.server.channel_name_translations().clone();
    let language = language(tag);
    wait_until(
        || translations.translate(&language, raw).as_deref() == Some(translated),
        &format!("{raw:?} to translate to {translated:?}"),
    )
    .await;
}

async fn create_channel(admin: &TestClient, name: &str) -> u32 {
    admin.create_channel(0, name, false).await;
    let Some(Message::ChannelState(state)) = admin
        .recv_until(
            |message| {
                matches!(message, Message::ChannelState(state)
                    if state.name.as_deref() == Some(name) && state.channel_id.is_some())
            },
            WAIT,
        )
        .await
    else {
        panic!("channel {name:?} was not created");
    };
    state.channel_id.expect("channel id")
}

async fn recv_channel_name(client: &TestClient, channel_id: u32, name: &str) {
    client
        .recv_until(
            |message| {
                matches!(message, Message::ChannelState(state)
                    if state.channel_id == Some(channel_id) && state.name.as_deref() == Some(name))
            },
            WAIT,
        )
        .await
        .unwrap_or_else(|| panic!("channel {channel_id} was not renamed to {name:?}"));
}

/// Wait until every `(channel_id, name)` pair has been received, in any order.
async fn recv_channel_names(client: &TestClient, expected: &[(u32, &str)]) {
    let mut missing: Vec<(u32, &str)> = expected.to_vec();
    tokio::time::timeout(WAIT, async {
        while !missing.is_empty() {
            let Some(message) = client.recv(WAIT).await else {
                return;
            };
            if let Message::ChannelState(state) = message {
                missing.retain(|(id, name)| {
                    !(state.channel_id == Some(*id) && state.name.as_deref() == Some(*name))
                });
            }
        }
    })
    .await
    .ok();
    assert!(missing.is_empty(), "channel names not received: {missing:?}");
}

fn initial_name(client: &TestClient, channel_id: u32) -> Option<&str> {
    client
        .initial_channel_states
        .iter()
        .find(|state| state.channel_id == Some(channel_id))
        .and_then(|state| state.name.as_deref())
}

/// Clients see channel names translated into their own language; clients
/// whose language has no translation see the names as entered.
#[tokio::test]
async fn channel_names_are_translated_for_each_client_language() {
    let mock = channel_name_component().await;
    let server = server_with_channel_names(&mock).await;
    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let lobby = create_channel(&admin, "Lobby").await;
    wait_for_translation(&server, "es", "Lobby", "Vestíbulo").await;

    let carmen = TestClient::connect_and_authenticate(&server, "carmen", None)
        .await
        .expect("carmen");
    let hans = TestClient::connect_and_authenticate(&server, "hans", None)
        .await
        .expect("hans");

    assert_eq!(initial_name(&carmen, lobby), Some("Vestíbulo"));
    assert_eq!(initial_name(&carmen, 0), Some("Raíz"));
    assert_eq!(initial_name(&hans, lobby), Some("Lobby"));
    assert_eq!(initial_name(&hans, 0), Some("Root"));
}

/// A translation saved in Weblate reaches connected clients without a
/// reconnect.
#[tokio::test]
async fn translation_updates_are_pushed_to_connected_clients() {
    let mock = channel_name_component().await;
    let server = server_with_channel_names(&mock).await;
    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let lobby = create_channel(&admin, "Lobby").await;
    wait_for_translation(&server, "es", "Lobby", "Vestíbulo").await;
    let carmen = TestClient::connect_and_authenticate(&server, "carmen", None)
        .await
        .expect("carmen");
    assert_eq!(initial_name(&carmen, lobby), Some("Vestíbulo"));

    mock.translate("es", "Lobby", "Sala de espera");

    recv_channel_name(&carmen, lobby, "Sala de espera").await;
}

/// Names Weblate does not know yet are added as source strings, and their
/// translations are then served.
#[tokio::test]
async fn new_channel_names_are_pushed_to_weblate() {
    let mock = channel_name_component().await;
    let server = server_with_channel_names(&mock).await;
    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let carmen = TestClient::connect_and_authenticate(&server, "carmen", None)
        .await
        .expect("carmen");

    let music = create_channel(&admin, "Music").await;
    recv_channel_name(&carmen, music, "Music").await;
    wait_until(
        || mock.source_keys().iter().any(|key| key == "Music"),
        "\"Music\" to be pushed to Weblate",
    )
    .await;
    assert!(
        mock.added_keys().iter().all(|key| key != "Lobby" && key != "Root"),
        "names Weblate already knows are not pushed again: {:?}",
        mock.added_keys()
    );
    assert!(
        mock.authorizations()
            .iter()
            .all(|header| header.as_deref() == Some("Token wlu_token"))
    );

    mock.translate("es", "Music", "Música");

    recv_channel_name(&carmen, music, "Música").await;
}

/// One name Weblate rejects must not block the rest of the batch. Names are
/// pushed in sorted order, so a batch that stops at the first error leaves
/// every later name unpushed and retries the same failing name first on every
/// poll.
#[tokio::test]
async fn a_rejected_name_does_not_block_the_other_pushes() {
    let mock = channel_name_component().await;
    // Armed before the channels exist, so no poll can push "Bad" successfully.
    mock.fail_add("Bad", 500);
    let server = server_with_channel_names(&mock).await;
    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    // Sorted push order is "Alpha", "Bad", "Zulu".
    create_channel(&admin, "Alpha").await;
    create_channel(&admin, "Bad").await;
    create_channel(&admin, "Zulu").await;

    wait_until(
        || {
            let keys = mock.source_keys();
            keys.iter().any(|key| key == "Alpha") && keys.iter().any(|key| key == "Zulu")
        },
        "\"Zulu\" to be pushed even though \"Bad\" is rejected",
    )
    .await;
    assert!(
        !mock.added_keys().iter().any(|key| key == "Bad"),
        "the rejected name is not recorded as pushed: {:?}",
        mock.added_keys()
    );

    mock.clear_add_failures();
    wait_until(
        || mock.source_keys().iter().any(|key| key == "Bad"),
        "the rejected name to be retried on a later poll",
    )
    .await;
}

/// Changing a connected client's language (as reauthentication can) re-sends
/// every channel name it can see, including reverting names that have no
/// translation in the new language.
#[tokio::test]
async fn language_change_resends_visible_channel_names() {
    let mock = channel_name_component().await;
    let server = server_with_channel_names(&mock).await;
    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let lobby = create_channel(&admin, "Lobby").await;
    wait_for_translation(&server, "es", "Lobby", "Vestíbulo").await;
    let carmen = TestClient::connect_and_authenticate(&server, "carmen", None)
        .await
        .expect("carmen");
    assert_eq!(initial_name(&carmen, lobby), Some("Vestíbulo"));
    let client = server
        .server
        .get_clients()
        .get_client_in_server(DEFAULT_SERVER_ID, carmen.server_session)
        .await
        .expect("server-side client");

    assert!(server.server.apply_client_language(&client, Some(language("de"))));
    server.server.refresh_client_language(&client).await;
    recv_channel_names(&carmen, &[(0, "Root"), (lobby, "Lobby")]).await;

    assert!(server.server.apply_client_language(&client, Some(language("es"))));
    server.server.refresh_client_language(&client).await;
    recv_channel_names(&carmen, &[(0, "Raíz"), (lobby, "Vestíbulo")]).await;

    assert!(
        !server.server.apply_client_language(&client, Some(language("es"))),
        "reapplying the same language is not a change"
    );
}

/// A client holding `no_channel_name_translation` is always shown the names as
/// entered, even in a translated language and even when the translations
/// change under it.
#[tokio::test]
async fn no_channel_name_translation_supplies_the_raw_names() {
    const QUIET: Duration = Duration::from_millis(300);
    let mock = channel_name_component().await;
    let server = server_with_channel_names(&mock).await;
    server
        .authenticator
        .register_user_with_language("carlos", None, Some(4), vec![], language("es-MX"));
    server.authenticator.set_privileges(
        "carlos",
        [shitspeak_auth::Privilege::NoChannelNameTranslation],
    );
    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let lobby = create_channel(&admin, "Lobby").await;
    wait_for_translation(&server, "es", "Lobby", "Vestíbulo").await;

    let carmen = TestClient::connect_and_authenticate(&server, "carmen", None)
        .await
        .expect("carmen");
    let carlos = TestClient::connect_and_authenticate(&server, "carlos", None)
        .await
        .expect("carlos");

    assert_eq!(initial_name(&carmen, lobby), Some("Vestíbulo"));
    assert_eq!(initial_name(&carmen, 0), Some("Raíz"));
    assert_eq!(initial_name(&carlos, lobby), Some("Lobby"));
    assert_eq!(initial_name(&carlos, 0), Some("Root"));

    mock.translate("es", "Lobby", "Sala de espera");

    recv_channel_name(&carmen, lobby, "Sala de espera").await;
    let unexpected = carlos
        .recv_until(|message| matches!(message, Message::ChannelState(_)), QUIET)
        .await;
    assert!(
        unexpected.is_none(),
        "a translation update must not re-send names to a no_channel_name_translation client: {unexpected:?}"
    );
}

/// The on-disk cache serves translations even when Weblate is unreachable at
/// startup.
#[tokio::test]
async fn channel_name_cache_serves_translations_while_weblate_is_down() {
    let mock = channel_name_component().await;
    let cache_dir = tempfile::tempdir().expect("temp dir");
    let cache_path = cache_dir.path().join("channel_names.json");
    let config = channel_names_config(&mock).with_cache_path(&cache_path);

    {
        let server = spawn_test_server(TestServerOpts {
            channel_name_translation: Some(config.clone()),
            ..TestServerOpts::default()
        })
        .await;
        wait_for_translation(&server, "es", "Root", "Raíz").await;
        wait_until(|| cache_path.exists(), "the cache file to be written").await;
        server.shutdown_gracefully().await;
    }

    mock.set_unavailable(true);
    let server = spawn_test_server(TestServerOpts {
        channel_name_translation: Some(config),
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user_with_language("carmen", None, Some(2), vec![], language("es"));
    let carmen = TestClient::connect_and_authenticate(&server, "carmen", None)
        .await
        .expect("carmen");
    assert_eq!(initial_name(&carmen, 0), Some("Raíz"));
}

/// Server text translated in Weblate applies to the next message generated,
/// without a restart, and falls back to the bundled catalog per string.
#[tokio::test]
async fn live_server_text_translations_apply_without_restart() {
    let mock = MockWeblate::start().await;
    mock.set_translation("en", true, &[("reject.WrongUserPw", "Incorrect username or password")]);
    mock.set_translation("es", false, &[("reject.WrongUserPw", "Credenciales no válidas")]);
    let server = spawn_test_server(TestServerOpts {
        default_language: language("es"),
        translation_sync: Some(
            TranslationSyncConfig::new(WeblateComponentConfig::new(
                mock.url(),
                "shitspeak",
                "server",
                None,
            ))
            .with_poll_interval(Duration::from_secs(1)),
        ),
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_user("alice", Some("hunter2"), Some(1), vec![]);
    let localizer = server.server.localizer().clone();
    wait_until(
        || {
            localizer.reject_reason(&language("es"), RejectType::WrongUserPw)
                == "Credenciales no válidas"
        },
        "the live Spanish translation",
    )
    .await;

    match TestClient::connect_and_authenticate(&server, "alice", Some("nope")).await {
        Err(ConnectError::Rejected(reject)) => {
            assert_eq!(reject.reason.as_deref(), Some("Credenciales no válidas"));
        }
        Err(other) => panic!("expected Rejected, got {other:?}"),
        Ok(_) => panic!("authentication should have failed"),
    }
    assert_eq!(
        localizer.reject_reason(&language("es"), RejectType::ServerFull),
        "El servidor está lleno",
        "strings Weblate does not provide keep their bundled translation"
    );
}

/// The reply to an ACL query opens Mumble's channel editor, which fills its
/// name field from the name the client currently shows. The reply is wrapped
/// so the editor gets the raw name while the channel tree keeps showing the
/// translation.
#[tokio::test]
async fn channel_editor_reply_shows_the_raw_name() {
    let mock = channel_name_component().await;
    let server = spawn_test_server(TestServerOpts {
        default_language: language("es"),
        channel_name_translation: Some(channel_names_config(&mock)),
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("admin", None, Some(1), vec!["admin".into()]);
    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    // A name Weblate does not know yet, so the creation echo is untranslated.
    let music = create_channel(&admin, "Music").await;
    wait_until(
        || mock.source_keys().iter().any(|key| key == "Music"),
        "\"Music\" to be pushed to Weblate",
    )
    .await;
    mock.translate("es", "Music", "Música");
    recv_channel_name(&admin, music, "Música").await;

    admin.query_acls(music).await;

    let mut sequence = Vec::new();
    tokio::time::timeout(WAIT, async {
        while sequence.last().map(String::as_str) != Some("name:Música")
            || !sequence.iter().any(|entry| entry == "acl")
        {
            match admin.recv(WAIT).await {
                Some(Message::ChannelState(state)) if state.channel_id == Some(music) => {
                    sequence.push(format!("name:{}", state.name.unwrap_or_default()));
                }
                Some(Message::ACL(acl)) if acl.channel_id == music => sequence.push("acl".to_owned()),
                Some(_) => {}
                None => break,
            }
        }
    })
    .await
    .expect("editor reply");
    assert_eq!(sequence, vec!["name:Music", "acl", "name:Música"]);
}

/// Saving the editor without touching the name sends the raw name back. That
/// must be a no-op, including for the root channel, which cannot be renamed:
/// no denial, no notice and no replicated change.
#[tokio::test]
async fn saving_the_editor_with_an_unchanged_name_is_a_no_op() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("admin", None, Some(1), vec!["admin".into()]);
    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let lobby = create_channel(&admin, "Lobby").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    admin.drain_now().await;
    let channels = server.server.get_channels().clone();
    let version = channels.current_version_in_server(DEFAULT_SERVER_ID);

    admin.update_channel_name(0, "Root").await;
    admin.update_channel_name(lobby, "Lobby").await;

    let unexpected = admin
        .recv_until(
            |message| {
                matches!(
                    message,
                    Message::PermissionDenied(_) | Message::TextMessage(_) | Message::ChannelState(_)
                )
            },
            Duration::from_millis(750),
        )
        .await;
    assert!(unexpected.is_none(), "unexpected response: {unexpected:?}");
    assert_eq!(channels.current_version_in_server(DEFAULT_SERVER_ID), version);
}
