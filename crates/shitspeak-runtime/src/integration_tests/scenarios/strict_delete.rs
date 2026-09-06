//! Durable deletion recovery using strict state copied from live nodes.
use crate::integration_tests::harness::{
    TestServerOpts, TestStrictReplicationState, spawn_s2s_test_server_with_state,
};
use shitspeak_core::DEFAULT_SERVER_ID;
use shitspeak_runtime_config::{S2sConfig, S2sSeedAddressConfig, S2sTransportKindConfig};
use shitspeak_s2s::testing::{loopback, mint_pki, pick_free_port, s2s_network_test_guard};
use shitspeak_state::{Channel, ChannelOp};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires live channel repositories and terminal journals copied through SSH"]
async fn strict_live_abandoned_delete_eventually_finishes_without_cancellation() {
    let _guard = s2s_network_test_guard().await;
    let root =
        PathBuf::from(std::env::var_os("SHITSPEAK_DELETE_STATE_ROOT").expect("fixture root"));
    let nodes = [
        (1, "wz"),
        (4, "eu"),
        (7, "sjc"),
        (8, "dfw"),
        (15, "jnb"),
        (16, "syd"),
    ];
    let ids = nodes.map(|(id, _)| id);
    let pki = Arc::new(mint_pki(&ids));
    let mut addresses = Vec::new();
    for _ in nodes {
        addresses.push(loopback(pick_free_port().await));
    }
    let mut servers = Vec::new();
    for (index, (id, directory)) in nodes.into_iter().enumerate() {
        let mut config = S2sConfig {
            enabled: true,
            tcp_listen: vec![addresses[index]],
            tcp_advertise: vec![addresses[index].to_string()],
            seed_addresses: addresses
                .iter()
                .copied()
                .filter(|a| *a != addresses[index])
                .map(|a| S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, a))
                .collect(),
            ..S2sConfig::default()
        };
        config.replications.delivery_tick_interval_ms = 50;
        config.replications.strict_bootstrap_retry_interval_ms = 500;
        servers.push(
            spawn_s2s_test_server_with_state(
                TestServerOpts::default(),
                Arc::clone(&pki),
                id,
                index,
                config,
                TestStrictReplicationState::from_directory(root.join(directory)),
            )
            .await,
        );
    }
    assert!(
        shitspeak_s2s::testing::wait_until(Duration::from_secs(90), || {
            servers.iter().enumerate().all(|(index, server)| {
                server
                    .server
                    .s2s_manager()
                    .overlay()
                    .is_some_and(|overlay| {
                        ids.iter().enumerate().all(|(peer_index, peer)| {
                            peer_index == index
                                || overlay
                                    .route_to(
                                        *peer,
                                        shitspeak_s2s_transport::ServiceLevel::Reliable,
                                    )
                                    .is_some()
                        })
                    })
            })
        })
        .await,
        "all copied nodes must join the local cluster"
    );
    let channel_id = 4_000_000_101;
    let source = &servers[0].server;
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if source
                .s2s_manager()
                .propose_channel_op(
                    DEFAULT_SERVER_ID,
                    ChannelOp::CreateChannel {
                        channel: Channel::new(
                            channel_id,
                            "abandoned-delete-reproduction",
                            0,
                            0,
                            Some(0),
                        ),
                    },
                )
                .await
                .is_proposed()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("cluster ready");
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let mut present = true;
            for server in &servers {
                present &= server
                    .server
                    .get_channels()
                    .get_channel_in_server(DEFAULT_SERVER_ID, channel_id)
                    .await
                    .is_some();
            }
            if present {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("created channel reaches every copied node");
    assert!(
        source
            .s2s_manager()
            .propose_channel_op(
                DEFAULT_SERVER_ID,
                ChannelOp::MarkPendingDelete {
                    id: channel_id,
                    nonce: 991,
                    evict_clients: true,
                }
            )
            .await
            .is_proposed()
    );
    // The proposer does no second phase. Every watchdog sees the same orphan.
    tokio::time::sleep(Duration::from_secs(15)).await;
    let mut cancellations = 0;
    let mut survivors = Vec::new();
    for (index, server) in servers.iter().enumerate() {
        let channels = server.server.get_channels();
        cancellations += channels
            .get_log_since_in_server(DEFAULT_SERVER_ID, 0)
            .await
            .iter()
            .filter(
                |op| matches!(op.op, ChannelOp::CancelPendingDelete { id, .. } if id == channel_id),
            )
            .count();
        if channels
            .get_channel_in_server(DEFAULT_SERVER_ID, channel_id)
            .await
            .is_some()
        {
            survivors.push(ids[index]);
        }
    }
    for server in servers {
        server.shutdown_gracefully().await;
    }
    assert_eq!(
        cancellations, 0,
        "watchdogs broadcast redundant cancellations; surviving nodes={survivors:?}"
    );
    assert!(
        survivors.is_empty(),
        "abandoned deletion survived on nodes {survivors:?}"
    );
}
#[tokio::test]
async fn deletion_rejects_a_late_local_move_and_listener_transaction() {
    use crate::integration_tests::harness::spawn_test_server;
    let server = spawn_test_server(TestServerOpts::default()).await;
    tokio::task::yield_now().await;
    let channels = server.server.get_channels();
    channels
        .create_channel_in_server(DEFAULT_SERVER_ID, Channel::new(7, "gone", 0, 0, Some(0)))
        .await
        .unwrap();
    channels
        .create_channel_in_server(DEFAULT_SERVER_ID, Channel::new(8, "stay", 0, 0, Some(0)))
        .await
        .unwrap();
    let clients = server.server.get_clients();
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let client = clients
        .allocate_web_client_in_server(
            DEFAULT_SERVER_ID,
            server.addr.ip(),
            server.addr,
            server.addr,
            tx,
        )
        .await;
    client.set_current_channel_id(
        8,
        clients,
        channels.current_version_in_server(DEFAULT_SERVER_ID),
    );
    channels
        .delete_channel_in_server(DEFAULT_SERVER_ID, 7)
        .await
        .unwrap();
    // A handler validated channel 7 before deletion and resumes afterwards.
    {
        let mut state = client.write_global_state(clients);
        state.set_current_channel_id(7);
        state.listen_channel(7);
    }
    assert_eq!(
        client.get_current_channel_id(),
        8,
        "a late move restored a deleted channel reference"
    );
    assert!(!client.get_listening_channel_ids().contains(&7));
    server.shutdown_gracefully().await;
}

async fn wait_for_channel_on_nodes(
    servers: &[crate::integration_tests::harness::TestServer],
    id: u32,
    present: bool,
) {
    let mut states = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            states.clear();
            for server in servers {
                let channels = server.server.get_channels();
                states.push((
                    channels.local_node_id(),
                    channels.current_version_in_server(DEFAULT_SERVER_ID),
                    channels
                        .get_channel_in_server(DEFAULT_SERVER_ID, id)
                        .await
                        .is_some(),
                ));
            }
            if states.iter().all(|(_, _, found)| *found == present) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if result.is_err() {
        let debug = servers
            .iter()
            .map(|server| {
                server
                    .server
                    .s2s_manager()
                    .strict_channel_debug_state_for_test(DEFAULT_SERVER_ID)
            })
            .collect::<Vec<_>>();
        panic!(
            "channel {id} expected present={present}; node/version/present={states:?}; strict={debug:#?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn irreversible_delete_survives_lost_duplicated_reordered_frames_and_offline_restart() {
    use crate::integration_tests::harness::spawn_s2s_test_server_with_config;
    use shitspeak_s2s::testing::{FaultSelector, LinkChaos, MessageType};
    use shitspeak_s2s_transport::{ServiceLevel, TransportKind};
    let _guard = s2s_network_test_guard().await;
    let ids = [1, 2, 3];
    let pki = Arc::new(mint_pki(&ids));
    let mut addresses = Vec::new();
    for _ in ids {
        addresses.push(loopback(pick_free_port().await));
    }
    let chaos = ids.map(|id| LinkChaos::with_seed(u64::from(id)));
    let mut configs = Vec::new();
    let mut servers = Vec::new();
    for index in 0..3 {
        let mut config = S2sConfig {
            enabled: true,
            tcp_listen: vec![addresses[index]],
            tcp_advertise: vec![addresses[index].to_string()],
            seed_addresses: addresses
                .iter()
                .copied()
                .filter(|address| *address != addresses[index])
                .map(|address| S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, address))
                .collect(),
            ..S2sConfig::default()
        };
        config.replications.delivery_tick_interval_ms = 50;
        config.replications.strict_bootstrap_retry_interval_ms = 500;
        config.replications.strict_steady_state_catchup_interval_ms = 1_000;
        configs.push(config.clone());
        servers.push(
            spawn_s2s_test_server_with_config(
                TestServerOpts {
                    s2s_inbound_chaos: Some(chaos[index].clone()),
                    ..TestServerOpts::default()
                },
                Arc::clone(&pki),
                ids[index],
                index,
                config,
            )
            .await,
        );
    }
    assert!(
        shitspeak_s2s::testing::wait_until(Duration::from_secs(30), || {
            servers.iter().enumerate().all(|(index, server)| {
                server
                    .server
                    .s2s_manager()
                    .overlay()
                    .is_some_and(|overlay| {
                        ids.iter().enumerate().all(|(peer_index, peer)| {
                            peer_index == index
                                || overlay.route_to(*peer, ServiceLevel::Reliable).is_some()
                        })
                    })
            })
        })
        .await,
        "three-node cluster ready"
    );
    for (id, parent) in [(100, 0), (101, 100), (102, 100)] {
        assert!(
            servers[0]
                .server
                .s2s_manager()
                .propose_channel_op(
                    DEFAULT_SERVER_ID,
                    ChannelOp::CreateChannel {
                        channel: Channel::new(id, format!("delete-chaos-{id}"), 0, 0, Some(parent)),
                    }
                )
                .await
                .is_proposed()
        );
        wait_for_channel_on_nodes(&servers, id, true).await;
    }
    let mut occupants = Vec::new();
    let mut receivers = Vec::new();
    for server in &servers {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        receivers.push(rx);
        let client = server
            .server
            .get_clients()
            .allocate_web_client_in_server(
                DEFAULT_SERVER_ID,
                server.addr.ip(),
                server.addr,
                server.addr,
                tx,
            )
            .await;
        {
            let mut state = client.write_global_state(server.server.get_clients());
            state.set_current_channel_id(101);
            state.listen_channel(101);
        }
        occupants.push(client);
    }
    for (index, faults) in chaos.iter().enumerate() {
        for peer in ids.iter().copied().filter(|peer| *peer != ids[index]) {
            for message in [
                MessageType::StrictPropose,
                MessageType::StrictCommit,
                MessageType::StrictAck,
            ] {
                let selector = FaultSelector::new(peer, TransportKind::Tcp, message);
                faults.set_duplication(selector, 1);
                faults.set_reorder(selector, Duration::from_millis(40));
            }
        }
    }
    chaos[2].drop_next_of_type(MessageType::StrictCommit, 1);
    let before = servers[0]
        .server
        .get_channels()
        .current_version_in_server(DEFAULT_SERVER_ID);
    assert!(
        servers[0]
            .server
            .s2s_manager()
            .propose_channel_op(
                DEFAULT_SERVER_ID,
                ChannelOp::DeleteChannel {
                    id: 101,
                    nonce: None,
                }
            )
            .await
            .is_proposed()
    );
    wait_for_channel_on_nodes(&servers, 101, false).await;
    for (index, server) in servers.iter().enumerate() {
        tokio::time::timeout(Duration::from_secs(10), async {
            while occupants[index].get_current_channel_id() != 100
                || occupants[index].get_listening_channel_ids().contains(&101)
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("local occupant and listener cleanup finish");
        assert!(!occupants[index].get_listening_channel_ids().contains(&101));
        let ops = server
            .server
            .get_channels()
            .get_log_since_in_server(DEFAULT_SERVER_ID, before)
            .await;
        assert_eq!(
            ops.len(),
            1,
            "duplicate network frames must not duplicate WAL records"
        );
        assert!(matches!(
            ops[0].op,
            ChannelOp::DeleteChannel {
                id: 101,
                nonce: None
            }
        ));
    }
    // Freeze an offline node's repository and terminal journal before another
    // deletion. Its restart must replay that decision without the requester.
    let captured = tempfile::tempdir().unwrap();
    servers[2]
        .server
        .get_channels()
        .save_snapshot()
        .await
        .unwrap();
    servers
        .pop()
        .unwrap()
        .shutdown_gracefully_and_capture_strict_state(captured.path())
        .await
        .unwrap();
    for faults in &chaos {
        for peer in ids {
            for message in [
                MessageType::StrictPropose,
                MessageType::StrictCommit,
                MessageType::StrictAck,
            ] {
                faults.clear_fault(FaultSelector::new(peer, TransportKind::Tcp, message));
            }
        }
    }
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if servers[0]
                .server
                .s2s_manager()
                .propose_channel_op(
                    DEFAULT_SERVER_ID,
                    ChannelOp::DeleteChannel {
                        id: 102,
                        nonce: None,
                    },
                )
                .await
                .is_proposed()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("surviving nodes commit deletion");
    wait_for_channel_on_nodes(&servers, 102, false).await;
    servers.push(
        spawn_s2s_test_server_with_state(
            TestServerOpts::default(),
            Arc::clone(&pki),
            3,
            2,
            configs[2].clone(),
            TestStrictReplicationState::from_directory(captured.path()),
        )
        .await,
    );
    wait_for_channel_on_nodes(&servers, 102, false).await;
    for server in &servers {
        assert!(
            server
                .server
                .get_channels()
                .get_channel_in_server(DEFAULT_SERVER_ID, 100)
                .await
                .is_some()
        );
        assert!(
            server
                .server
                .get_channels()
                .get_log_since_in_server(DEFAULT_SERVER_ID, before)
                .await
                .iter()
                .all(|op| !matches!(
                    op.op,
                    ChannelOp::MarkPendingDelete { .. } | ChannelOp::CancelPendingDelete { .. }
                ))
        );
    }
    for server in servers {
        server.shutdown_gracefully().await;
    }
}
