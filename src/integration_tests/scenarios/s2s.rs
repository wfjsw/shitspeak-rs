//! S2S-enabled server scenarios.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::ban_repository::{BanEntry, BanOp};
use crate::config::{S2sSeedAddressConfig, S2sTransportKindConfig};
use crate::integration_tests::harness::{
    spawn_s2s_test_server, TestClient, TestS2sServerOpts, TestServer, TestServerOpts,
};
use crate::messages::encoder::{PluginDataTransmission, UserStats};
use crate::messages::Message;
use crate::s2s::testing::{loopback, mint_pki, pick_free_port, wait_until};
use crate::s2s::transport::ServiceLevel;
use crate::voice::codec::AudioPayload;

const S2S_DEADLINE: Duration = Duration::from_secs(10);
const CLIENT_DEADLINE: Duration = Duration::from_secs(4);
const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

static S2S_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn spawn_s2s_pair() -> (TestServer, TestServer) {
    let pki = Arc::new(mint_pki(&[1, 2]));
    let a_s2s_port = pick_free_port().await;
    let b_s2s_port = pick_free_port().await;

    let a = spawn_s2s_test_server(
        TestServerOpts::default(),
        Arc::clone(&pki),
        TestS2sServerOpts {
            node_id: 1,
            cert_index: 0,
            tcp_listen: loopback(a_s2s_port),
            seed_addresses: vec![S2sSeedAddressConfig::new(
                S2sTransportKindConfig::Tcp,
                loopback(b_s2s_port),
            )],
        },
    )
    .await;

    let b = spawn_s2s_test_server(
        TestServerOpts::default(),
        pki,
        TestS2sServerOpts {
            node_id: 2,
            cert_index: 1,
            tcp_listen: loopback(b_s2s_port),
            seed_addresses: vec![S2sSeedAddressConfig::new(
                S2sTransportKindConfig::Tcp,
                loopback(a_s2s_port),
            )],
        },
    )
    .await;

    (a, b)
}

async fn wait_for_s2s_pair(a: &TestServer, b: &TestServer) {
    let ready = wait_until(S2S_DEADLINE, || {
        let a_mgr = a.server.s2s_manager();
        let b_mgr = b.server.s2s_manager();
        let a_overlay = a_mgr.overlay();
        let b_overlay = b_mgr.overlay();

        a_mgr.application().is_some()
            && b_mgr.application().is_some()
            && a_mgr.replications().is_some()
            && b_mgr.replications().is_some()
            && a_overlay.as_ref().map_or(false, |overlay| {
                overlay.alive_members().contains(&2)
                    && overlay.route_to(2, ServiceLevel::Reliable).is_some()
            })
            && b_overlay.as_ref().map_or(false, |overlay| {
                overlay.alive_members().contains(&1)
                    && overlay.route_to(1, ServiceLevel::Reliable).is_some()
            })
    })
    .await;

    assert!(ready, "S2S pair did not discover each other in time");
}

fn register_pair_users(a: &TestServer, b: &TestServer) {
    a.authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    b.authenticator.register_user("bob", None, Some(2), vec![]);
}

fn opus_frame(payload: &AudioPayload) -> &[u8] {
    match payload {
        AudioPayload::Opus(opus) => &opus.frame,
        other => panic!("expected Opus payload, got {other:?}"),
    }
}

/// Checks that two S2S-enabled servers discover each other from configured seed
/// addresses that do not include node ids.
/// Expected: the pair converges and both servers expose an S2S application
/// layer. Mumble has no upstream S2S layer; the client-visible expectation is
/// still normal Murmur behavior from `D:\mumble\src\murmur`, while the local
/// S2S extension follows shitspeak's side-channel precedent in
/// `D:\shitspeak\slavehub.go` and this crate's S2S overlay design.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_enabled_servers_discover_seed_addresses_without_node_ids() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;

    wait_for_s2s_pair(&a, &b).await;

    assert!(a.server.s2s_manager().application().is_some());
    assert!(b.server.s2s_manager().application().is_some());
}

/// Checks a cross-node `UserStats` request.
/// Expected: Alice on server A receives Bob's `UserStats` from server B with
/// the requested `stats_only` flag. The stats response shape comes from
/// `D:\mumble\src\Mumble.proto` and `D:\mumble\src\murmur\Messages.cpp::msgUserStats`;
/// shitspeak mirrors that handler in `D:\shitspeak\message.go::handleUserStatsMessage`,
/// while this crate extends delivery across S2S.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_user_stats_rpc() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    alice
        .send(
            UserStats {
                session: Some(bob.session_id),
                stats_only: Some(true),
                ..UserStats::default()
            }
            .into(),
        )
        .await;

    let msg = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserStats(us)
                    if us.session == Some(bob.session_id) && us.stats_only == Some(true))
            },
            CLIENT_DEADLINE,
        )
        .await;

    assert!(msg.is_some(), "Alice should receive Bob's cross-node stats");
}

/// Checks cross-node plugin data routing to explicitly targeted receiver sessions.
/// Expected: Bob receives Alice's `PluginDataTransmission` with the sender
/// stamped by server A and the payload preserved over S2S.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_plugin_data_transmission_routes_to_remote_recipient() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    let payload = Bytes::from_static(b"plugin-payload");
    alice
        .send(
            PluginDataTransmission {
                sender_session: Some(999),
                receiver_sessions: vec![bob.session_id, bob.session_id, alice.session_id],
                data: Some(payload.clone()),
                data_id: Some("plugin.data.test".to_string()),
            }
            .into(),
        )
        .await;

    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::PluginDataTransmission(p)
                    if p.sender_session == Some(alice.session_id)
                        && p.receiver_sessions == vec![bob.session_id]
                        && p.data.as_ref() == Some(&payload)
                        && p.data_id.as_deref() == Some("plugin.data.test"))
            },
            CLIENT_DEADLINE,
        )
        .await;

    assert!(
        msg.is_some(),
        "Bob should receive Alice's cross-node plugin data"
    );
}

/// Checks cross-node moderation routing to the target user's owning server.
/// Expected: Alice's mute request on server A is applied by server B and Bob
/// receives `UserState { mute: true }`. The moderation semantics come from
/// Mumble's `D:\mumble\src\murmur\Messages.cpp::msgUserState` and shitspeak's
/// `D:\shitspeak\message.go::handleUserStateMessage`; S2S adds the owner-hop
/// delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_moderation_applies_to_owner() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    let bob_known_on_a = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(a.server.get_clients().get_client(bob.server_session.into()))
                .is_some()
        })
    })
    .await;
    assert!(
        bob_known_on_a,
        "Server A should materialize Bob before dispatching moderated UserState"
    );

    alice.mute_other(bob.session_id, true).await;

    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob.session_id) && us.mute == Some(true))
            },
            CLIENT_DEADLINE,
        )
        .await;

    assert!(msg.is_some(), "Bob should receive the cross-node mute");
}

/// Checks cross-node normal-channel voice routing.
/// Expected: Bob on server B receives Alice's Opus frame from server A with
/// Alice's server-session id. Voice routing semantics come from
/// `D:\mumble\src\murmur\Server.cpp::processMsg` and shitspeak's
/// `D:\shitspeak\client.go`; this crate extends the receiver set over S2S.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_voice_routes_normal_channel() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    alice
        .send_voice_tcp(0, 1, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob
        .recv_voice_tcp(CLIENT_DEADLINE)
        .await
        .expect("Bob should receive Alice's cross-node voice");

    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
}

/// Checks that channel creation is replicated to another S2S node.
/// Expected: Bob receives `ChannelState` for `S2S Lobby` and server B advances
/// its channel log. Channel semantics come from Mumble's
/// `D:\mumble\src\murmur\Messages.cpp::msgChannelState` and shitspeak's
/// `D:\shitspeak\message.go::handleChannelStateMessage`; this crate's S2S
/// replication supplies the cross-node log propagation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_channel_replication_propagates() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    alice.create_channel(0, "S2S Lobby", false).await;

    let saw_bob = bob
        .recv_until(
            |m| matches!(m, Message::ChannelState(cs) if cs.name.as_deref() == Some("S2S Lobby")),
            S2S_DEADLINE,
        )
        .await;
    assert!(
        saw_bob.is_some(),
        "Bob should receive the replicated channel creation"
    );

    let replicated = wait_until(S2S_DEADLINE, || {
        b.server.get_channels().current_version() >= a.server.get_channels().current_version()
    })
    .await;
    assert!(replicated, "Server B should advance its channel log");
}

/// Checks client add, update, and remove replication across S2S nodes.
/// Expected: Bob sees Alice join, self-mute, and leave, and server B's remote
/// client index materializes then removes Alice. The user-state/remove
/// behavior comes from Mumble's `D:\mumble\src\murmur\Messages.cpp` and
/// shitspeak's `D:\shitspeak\message.go`; this crate's S2S client repository
/// replication extends it across servers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_client_replication_propagates_add_update_remove() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    let alice_session = alice.server_session;
    let alice_session_wire = u32::from(alice_session);
    let indexed_add = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(b.server.get_clients().get_client(alice_session.into()))
                .is_some()
        })
    })
    .await;
    assert!(
        indexed_add,
        "Server B should materialize Alice in its remote index"
    );

    let saw_add =
        bob.initial_user_states.iter().any(|us| {
            us.session == Some(alice_session_wire) && us.name.as_deref() == Some("alice")
        }) || bob
            .recv_until(
                |m| {
                    matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session_wire)
                        && us.name.as_deref() == Some("alice"))
                },
                S2S_DEADLINE,
            )
            .await
            .is_some();
    assert!(saw_add, "Bob should see Alice's replicated add");

    alice.set_self_mute(true).await;
    let saw_update = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice_session_wire) && us.self_mute == Some(true))
            },
            S2S_DEADLINE,
        )
        .await;
    assert!(
        saw_update.is_some(),
        "Bob should see Alice's replicated state update"
    );

    drop(alice);
    let saw_remove = bob
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == alice_session_wire),
            S2S_DEADLINE,
        )
        .await;
    assert!(
        saw_remove.is_some(),
        "Bob should see Alice's replicated removal"
    );

    let removed = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(b.server.get_clients().get_client(alice_session.into()))
                .is_none()
        })
    })
    .await;
    assert!(
        removed,
        "Server B should remove Alice from its remote index"
    );
}

/// Checks that a reconnecting client receives other replicated users in their
/// actual channels, even though the reconnecting client itself starts in root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_reconnect_initial_snapshot_preserves_remote_user_channel() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    a.server
        .get_channels()
        .create_channel(crate::channels::Channel::new(
            42,
            "S2S Lobby".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .expect("create replicated channel");

    let channel_replicated = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(b.server.get_channels().get_channel(42))
                .is_some()
        })
    })
    .await;
    assert!(channel_replicated, "Server B should know channel 42");

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    alice.move_to_channel(42).await;
    bob.move_to_channel(42).await;

    let alice_materialized_on_b = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            let client = tokio::runtime::Handle::current()
                .block_on(b.server.get_clients().get_client(alice.server_session));
            client.is_some_and(|client| client.get_current_channel_id() == 42)
        })
    })
    .await;
    assert!(
        alice_materialized_on_b,
        "Server B should track Alice in channel 42 before Bob reconnects; channel_version={}, client_versions={:?}, alice_channel={:?}",
        b.server.get_channels().current_version(),
        b.server.get_clients().snapshot_with_versions().await.1,
        b.server
            .get_clients()
            .get_client(alice.server_session)
            .await
            .map(|client| client.get_current_channel_id())
    );

    let bob_materialized_on_a = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            let client = tokio::runtime::Handle::current()
                .block_on(a.server.get_clients().get_client(bob.server_session));
            client.is_some_and(|client| client.get_current_channel_id() == 42)
        })
    })
    .await;
    assert!(
        bob_materialized_on_a,
        "Server A should track Bob in channel 42 before Bob disconnects"
    );

    let old_bob_session = bob.server_session;
    drop(bob);

    let old_bob_removed = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(a.server.get_clients().get_client(old_bob_session))
                .is_none()
        })
    })
    .await;
    assert!(old_bob_removed, "Server A should remove old Bob");

    let bob_reconnected = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob reconnect");

    let alice_wire_session = u32::from(alice.server_session);
    let alice_state = bob_reconnected
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(alice_wire_session));
    assert_eq!(
        alice_state.and_then(|state| state.channel_id),
        Some(42),
        "Bob's reconnect burst should keep Alice in channel 42"
    );

    let bob_state = bob_reconnected
        .initial_user_states
        .iter()
        .find(|state| state.session == Some(bob_reconnected.session_id));
    assert_eq!(
        bob_state.and_then(|state| state.channel_id),
        Some(0),
        "Bob reconnects into root until last-channel persistence exists"
    );
}

/// Checks that a ban operation proposed on one S2S node appears on another.
/// Expected: server B's active ban list contains the proposed ban reason after
/// server A accepts the S2S proposal. Ban semantics come from Mumble's
/// `D:\mumble\src\murmur\Messages.cpp::msgBanList` and shitspeak's
/// `D:\shitspeak\ban.go`; this crate's S2S ban replication supplies the
/// cross-node propagation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_ban_replication_propagates() {
    let _guard = S2S_TEST_LOCK.lock().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let entry = BanEntry {
        address: "203.0.113.17".parse().unwrap(),
        mask: 32,
        name: Some("replicated-ban".into()),
        hash: None,
        reason: Some("s2s integration test".into()),
        start: chrono::Utc::now().timestamp(),
        duration: 0,
    };

    let proposed = tokio::time::timeout(
        S2S_DEADLINE,
        a.server
            .s2s_manager()
            .propose_ban_op(BanOp::AddBan { entry }),
    )
    .await
    .unwrap_or(false);
    assert!(proposed, "Server A should accept the S2S ban proposal");

    let replicated = wait_until(S2S_DEADLINE, || {
        let bans = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(b.server.get_bans().get_active_bans())
        });
        bans.iter()
            .any(|entry| entry.reason.as_deref() == Some("s2s integration test"))
    })
    .await;

    assert!(replicated, "Server B should contain the replicated ban");
}
