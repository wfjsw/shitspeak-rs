//! S2S-enabled server scenarios.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{
    future::join_all,
    stream::{FuturesUnordered, StreamExt},
};

use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::integration_tests::harness::{
    TestClient, TestS2sServerOpts, TestServer, TestServerOpts, spawn_s2s_test_server,
    spawn_s2s_test_server_with_config, test_client::ConnectError,
};
use crate::messages::Message;
use crate::messages::encoder::{Ping, PluginDataTransmission, TextMessage, UserStats, VoiceTarget};
use crate::mumble_proto::voice_target::Target as VoiceTargetEntry;
use crate::voice::codec::AudioPayload;
use crate::voice::metrics::{
    VoiceRouteKind, VoiceRouteSource, route_metric_snapshot, route_resolution_metric_snapshot,
};
use shitspeak_runtime_config::{S2sConfig, S2sSeedAddressConfig, S2sTransportKindConfig};
use shitspeak_s2s::testing::{
    LinkChaos, MessageType, Pki, loopback, mint_pki, pick_free_port, pick_free_udp_port,
    s2s_network_test_guard, wait_until, wait_until_with,
};
use shitspeak_s2s_transport::{
    MessageClass, PeerAddress, SendOptions, ServiceLevel, TransportKind,
};
use shitspeak_state::Channel;
use shitspeak_state::{BanEntry, BanOp};

const S2S_DEADLINE: Duration = Duration::from_secs(10);
const CLIENT_DEADLINE: Duration = Duration::from_secs(4);
const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
const S2S_SHOUT_REMOTE_CLIENTS: usize = 500;
const S2S_SHOUT_CHANNEL_ID: u32 = 42;
const S2S_SHOUT_TARGET_SLOT: u32 = 7;
const S2S_SHOUT_FRAMES: usize = 501;
const S2S_SHOUT_FRAME_INTERVAL: Duration = Duration::from_millis(20);
const S2S_SHOUT_MIN_SPEAK_SPAN: Duration = Duration::from_secs(10);
const S2S_SHOUT_CONNECT_DEADLINE: Duration = Duration::from_secs(600);
const S2S_SHOUT_CONNECT_ATTEMPT_DEADLINE: Duration = Duration::from_secs(60);
const S2S_SHOUT_CONNECT_ATTEMPTS: usize = 3;
const S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS: u64 = 600_000;
const S2S_SHOUT_AUTH_FINALIZATION_CONCURRENCY: usize = 64;
// A 500-recipient fanout is intentionally a throughput stress test. Preserve
// the tighter inter-frame continuity budget below, while allowing a bounded
// host-scheduler tail for the final UDP batches.
const S2S_SHOUT_FRAME_LATENCY_BUDGET: Duration = Duration::from_secs(3);
const S2S_SHOUT_STREAM_GAP_BUDGET: Duration = Duration::from_millis(250);
// The bad-node scenario deliberately forces a route failover mid-talkspurt.
// Keep normal fanout at 250 ms while allowing the repaired TCP stream to
// settle without treating the intentional fault as a media-loss regression.
const S2S_SHOUT_BAD_NODE_STREAM_GAP_BUDGET: Duration = Duration::from_millis(750);
const S2S_SHOUT_LOSS_BUDGET_PERCENT: usize = 1;
const S2S_SHOUT_ROUTE_CPU_BUDGET: f64 = 0.40;
const S2S_LONG_HAUL_ONE_WAY_LATENCY: Duration = Duration::from_millis(104);
const S2S_LONG_HAUL_JITTER: Duration = Duration::from_millis(4);
const S2S_LONG_HAUL_FRAME_COUNT: usize = 48;
const S2S_LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET: Duration = Duration::from_millis(400);
const S2S_ROOT_SHOUT_TRAFFIC_CHANNELS: &[(u32, u32, &str)] = &[
    (10, 0, "General"),
    (11, 10, "General East"),
    (12, 10, "General West"),
    (20, 0, "Operations"),
    (21, 20, "Operations East"),
    (22, 20, "Operations West"),
    (30, 0, "Support"),
    (31, 30, "Support East"),
    (32, 30, "Support West"),
];
const CONVERGENCE_NODE_COUNT: u16 = 6;
const CONVERGENCE_USERS_PER_NODE: usize = 800;
const CONVERGENCE_LIGHT_USERS_PER_NODE: usize = 20;
const CONVERGENCE_HELLO_INTERVAL_MS: u64 = 200;
const CONVERGENCE_HELLO_DEAD_INTERVAL_MS: u64 = 800;
const CONVERGENCE_LSA_MAX_AGE_MS: u64 = 5_000;
const S2S_LAG_DIAGNOSTIC_NODE_COUNT: u16 = 8;
const S2S_LAG_DIAGNOSTIC_CLIENTS_ON_NODE: usize = 150;
const S2S_LAG_DIAGNOSTIC_CHANNEL_ID: u32 = 42;
const S2S_LAG_DIAGNOSTIC_BASE_LATENCY_MS: u64 = 400;
const S2S_LAG_DIAGNOSTIC_SLOW_LINK_LATENCY_MS: u64 = 16_000;
const S2S_LAG_DIAGNOSTIC_HELLO_DEAD_MS: u64 = 45_000;
const S2S_LAG_DIAGNOSTIC_LSA_MAX_AGE_MS: u64 = 90_000;
const S2S_LAG_DIAGNOSTIC_OUTBOUND_CAPACITY: usize = 8;
const S2S_LAG_DIAGNOSTIC_REMOTE_WAIT_SECS: u64 = 35;

async fn spawn_s2s_pair() -> (TestServer, TestServer) {
    spawn_s2s_pair_with_opts(TestServerOpts::default(), TestServerOpts::default()).await
}

async fn spawn_s2s_pair_with_opts(
    a_opts: TestServerOpts,
    b_opts: TestServerOpts,
) -> (TestServer, TestServer) {
    let pki = Arc::new(mint_pki(&[1, 2]));
    let a_s2s_port = pick_free_port().await;
    let b_s2s_port = pick_free_port().await;

    let a = spawn_s2s_test_server(
        a_opts,
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
        b_opts,
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

async fn spawn_targeted_s2s_pair() -> (TestServer, TestServer) {
    let pki = Arc::new(mint_pki(&[1, 2]));
    let a_s2s_port = pick_free_port().await;
    let b_s2s_port = pick_free_port().await;

    let mut a_config = S2sConfig {
        enabled: true,
        tcp_listen: vec![loopback(a_s2s_port)],
        seed_addresses: vec![S2sSeedAddressConfig::new(
            S2sTransportKindConfig::Tcp,
            loopback(b_s2s_port),
        )],
        ..S2sConfig::default()
    };
    a_config.application.voice.delivery_strategy = "targeted".to_owned();
    let mut b_config = S2sConfig {
        enabled: true,
        tcp_listen: vec![loopback(b_s2s_port)],
        seed_addresses: vec![S2sSeedAddressConfig::new(
            S2sTransportKindConfig::Tcp,
            loopback(a_s2s_port),
        )],
        ..S2sConfig::default()
    };
    b_config.application.voice.delivery_strategy = "targeted".to_owned();

    let a = spawn_s2s_test_server_with_config(
        TestServerOpts::default(),
        Arc::clone(&pki),
        1,
        0,
        a_config,
    )
    .await;
    let b = spawn_s2s_test_server_with_config(TestServerOpts::default(), pki, 2, 1, b_config).await;

    (a, b)
}

/// Start the long-haul production shape directly: node 8 is the source and
/// node 1 is the receiver. Each direction is delayed independently so Hello,
/// tree control, voice, and repair all see an approximately 208 ms RTT.
async fn spawn_s2s_long_haul_pair() -> (TestServer, TestServer) {
    let pki = Arc::new(mint_pki(&[8, 1]));
    let node_8_port = pick_free_port().await;
    let node_1_port = pick_free_port().await;
    let node_8_chaos = LinkChaos::new();
    let node_1_chaos = LinkChaos::new();
    node_8_chaos.add_latency(1, S2S_LONG_HAUL_ONE_WAY_LATENCY);
    node_1_chaos.add_latency(8, S2S_LONG_HAUL_ONE_WAY_LATENCY);
    node_8_chaos.set_jitter(Some(S2S_LONG_HAUL_JITTER));
    node_1_chaos.set_jitter(Some(S2S_LONG_HAUL_JITTER));

    let mut node_8_config = S2sConfig {
        enabled: true,
        tcp_listen: vec![loopback(node_8_port)],
        seed_addresses: vec![S2sSeedAddressConfig::new(
            S2sTransportKindConfig::Tcp,
            loopback(node_1_port),
        )],
        ..S2sConfig::default()
    };
    node_8_config.application.voice.tree_delivery_enabled = true;
    let mut node_1_config = S2sConfig {
        enabled: true,
        tcp_listen: vec![loopback(node_1_port)],
        seed_addresses: vec![S2sSeedAddressConfig::new(
            S2sTransportKindConfig::Tcp,
            loopback(node_8_port),
        )],
        ..S2sConfig::default()
    };
    node_1_config.application.voice.tree_delivery_enabled = true;

    let node_8 = spawn_s2s_test_server_with_config(
        TestServerOpts {
            max_users: 16,
            s2s_inbound_chaos: Some(node_8_chaos),
            ..TestServerOpts::default()
        },
        Arc::clone(&pki),
        8,
        0,
        node_8_config,
    )
    .await;
    let node_1 = spawn_s2s_test_server_with_config(
        TestServerOpts {
            max_users: 16,
            s2s_inbound_chaos: Some(node_1_chaos),
            ..TestServerOpts::default()
        },
        pki,
        1,
        1,
        node_1_config,
    )
    .await;

    (node_8, node_1)
}

async fn spawn_s2s_three_node_with_opts(
    a_opts: TestServerOpts,
    b_opts: TestServerOpts,
    c_opts: TestServerOpts,
) -> (TestServer, TestServer, TestServer) {
    let pki = Arc::new(mint_pki(&[1, 2, 3]));
    let a_s2s_port = pick_free_port().await;
    let b_s2s_port = pick_free_port().await;
    let c_s2s_port = pick_free_port().await;

    let a = spawn_s2s_test_server(
        a_opts,
        Arc::clone(&pki),
        TestS2sServerOpts {
            node_id: 1,
            cert_index: 0,
            tcp_listen: loopback(a_s2s_port),
            seed_addresses: vec![
                S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, loopback(b_s2s_port)),
                S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, loopback(c_s2s_port)),
            ],
        },
    )
    .await;

    let b = spawn_s2s_test_server(
        b_opts,
        Arc::clone(&pki),
        TestS2sServerOpts {
            node_id: 2,
            cert_index: 1,
            tcp_listen: loopback(b_s2s_port),
            seed_addresses: vec![
                S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, loopback(a_s2s_port)),
                S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, loopback(c_s2s_port)),
            ],
        },
    )
    .await;

    let c = spawn_s2s_test_server(
        c_opts,
        pki,
        TestS2sServerOpts {
            node_id: 3,
            cert_index: 2,
            tcp_listen: loopback(c_s2s_port),
            seed_addresses: vec![
                S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, loopback(a_s2s_port)),
                S2sSeedAddressConfig::new(S2sTransportKindConfig::Tcp, loopback(b_s2s_port)),
            ],
        },
    )
    .await;

    (a, b, c)
}

async fn spawn_s2s_pair_on_ports(
    pki: Arc<Pki>,
    a_s2s_port: u16,
    b_s2s_port: u16,
) -> (TestServer, TestServer) {
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

async fn spawn_s2s_node_b(pki: Arc<Pki>, a_s2s_port: u16, b_s2s_port: u16) -> TestServer {
    spawn_s2s_test_server(
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
    .await
}

fn all_transport_s2s_config(
    tcp_listen: std::net::SocketAddr,
    kcp_listen: std::net::SocketAddr,
    quic_listen: std::net::SocketAddr,
    udp_listen: std::net::SocketAddr,
    seed_tcp: std::net::SocketAddr,
) -> S2sConfig {
    S2sConfig {
        enabled: true,
        tcp_listen: vec![tcp_listen],
        kcp_listen: vec![kcp_listen],
        quic_listen: vec![quic_listen],
        udp_listen: vec![udp_listen],
        tcp_advertise: vec![tcp_listen.to_string()],
        kcp_advertise: vec![kcp_listen.to_string()],
        quic_advertise: vec![quic_listen.to_string()],
        udp_advertise: vec![udp_listen.to_string()],
        seed_addresses: vec![S2sSeedAddressConfig::new(
            S2sTransportKindConfig::Tcp,
            seed_tcp,
        )],
        ..S2sConfig::default()
    }
}

fn fast_owner_catchup_s2s_config(
    tcp_listen: std::net::SocketAddr,
    seed_addresses: Vec<S2sSeedAddressConfig>,
) -> S2sConfig {
    let mut config = S2sConfig {
        enabled: true,
        tcp_listen: vec![tcp_listen],
        seed_addresses,
        ..S2sConfig::default()
    };
    config.replications.owner_catchup_timeout_ms = 250;
    config.replications.owner_anti_entropy_interval_ms = 250;
    config
}

async fn wait_for_s2s_pair(a: &TestServer, b: &TestServer) {
    let ready = wait_until(S2S_DEADLINE, || {
        let a_mgr = a.server.s2s_manager();
        let b_mgr = b.server.s2s_manager();
        let a_overlay = a_mgr.overlay();
        let b_overlay = b_mgr.overlay();
        let a_transport = a_mgr.transport();
        let b_transport = b_mgr.transport();

        a_mgr.application().is_some()
            && b_mgr.application().is_some()
            && a_mgr.replications().is_some()
            && b_mgr.replications().is_some()
            && a_transport
                .as_ref()
                .is_some_and(|transport| !transport.live_transport_kinds(2).is_empty())
            && b_transport
                .as_ref()
                .is_some_and(|transport| !transport.live_transport_kinds(1).is_empty())
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

async fn wait_for_s2s_cluster(nodes: &[(&TestServer, u16)]) {
    let ready = wait_until(S2S_DEADLINE, || {
        nodes.iter().all(|(server, node_id)| {
            let mgr = server.server.s2s_manager();
            let Some(overlay) = mgr.overlay() else {
                return false;
            };
            let Some(transport) = mgr.transport() else {
                return false;
            };
            mgr.application().is_some()
                && mgr.replications().is_some()
                && nodes.iter().all(|(_, peer_id)| {
                    node_id == peer_id
                        || (overlay.alive_members().contains(peer_id)
                            && overlay.route_to(*peer_id, ServiceLevel::Reliable).is_some()
                            && overlay
                                .route_to_with_metric(
                                    *peer_id,
                                    ServiceLevel::BestEffort,
                                    shitspeak_s2s::overlay::RoutingMetric::ConversationalQuality,
                                )
                                .is_some_and(|next_hop| {
                                    !transport.live_transport_kinds(next_hop).is_empty()
                                }))
                })
        })
    })
    .await;

    assert!(ready, "S2S cluster did not converge in time");
}

struct ConvergenceCluster {
    servers: Vec<TestServer>,
    s2s_ports: Vec<u16>,
}

impl ConvergenceCluster {
    async fn connect_full_mesh(&self) {
        for (idx, server) in self.servers.iter().enumerate() {
            for (peer_idx, &peer_port) in self.s2s_ports.iter().enumerate() {
                if idx == peer_idx {
                    continue;
                }
                add_s2s_peer_address(server, (peer_idx + 1) as u16, peer_port).await;
            }
        }
    }
}

async fn spawn_s2s_convergence_cluster() -> ConvergenceCluster {
    spawn_s2s_convergence_cluster_with_voice_options(true, None, None, None).await
}

async fn spawn_s2s_convergence_cluster_with_tree_delivery(
    tree_delivery_enabled: bool,
) -> ConvergenceCluster {
    spawn_s2s_convergence_cluster_with_voice_options(tree_delivery_enabled, None, None, None).await
}

async fn spawn_s2s_convergence_cluster_with_voice_options(
    tree_delivery_enabled: bool,
    repair_max_extra_copies_per_frame: Option<usize>,
    reorder_delay_ms: Option<u64>,
    reorder_max_buffered_frames: Option<usize>,
) -> ConvergenceCluster {
    let node_ids: Vec<u16> = (1..=CONVERGENCE_NODE_COUNT).collect();
    let pki = Arc::new(mint_pki(&node_ids));
    let mut ports = Vec::with_capacity(node_ids.len());
    for _ in &node_ids {
        ports.push(pick_free_port().await);
    }

    let mut servers = Vec::with_capacity(node_ids.len());
    for (idx, &node_id) in node_ids.iter().enumerate() {
        let mut opts = TestServerOpts::default();
        opts.max_users = (CONVERGENCE_USERS_PER_NODE
            + CONVERGENCE_LIGHT_USERS_PER_NODE * (usize::from(CONVERGENCE_NODE_COUNT) - 1)
            + 8) as u64;
        let mut s2s = S2sConfig {
            enabled: true,
            tcp_listen: vec![loopback(ports[idx])],
            seed_addresses: Vec::new(),
            ..S2sConfig::default()
        };
        s2s.overlay.hello_interval_ms = CONVERGENCE_HELLO_INTERVAL_MS;
        s2s.overlay.hello_dead_interval_ms = CONVERGENCE_HELLO_DEAD_INTERVAL_MS;
        s2s.overlay.lsa_max_age_ms = CONVERGENCE_LSA_MAX_AGE_MS;
        s2s.overlay.lsa_flood_pacing_interval_ms = 50;
        s2s.overlay.cost_rerun_min_interval_ms = 50;
        s2s.application.voice.tree_delivery_enabled = tree_delivery_enabled;
        if let Some(repair_max_extra_copies_per_frame) = repair_max_extra_copies_per_frame {
            s2s.application.voice.repair_max_extra_copies_per_frame =
                repair_max_extra_copies_per_frame;
        }
        if let Some(reorder_delay_ms) = reorder_delay_ms {
            s2s.application.voice.reorder_max_delay_ms = reorder_delay_ms;
            s2s.application.voice.adaptive_jitter_min_delay_ms = reorder_delay_ms;
            s2s.application.voice.adaptive_jitter_max_delay_ms = reorder_delay_ms;
        }
        if let Some(reorder_max_buffered_frames) = reorder_max_buffered_frames {
            s2s.application.voice.reorder_max_buffered_frames = reorder_max_buffered_frames;
        }
        servers.push(
            spawn_s2s_test_server_with_config(opts, Arc::clone(&pki), node_id, idx, s2s).await,
        );
    }
    for server in &servers {
        wait_for_s2s_runtime(server).await;
    }
    ConvergenceCluster {
        servers,
        s2s_ports: ports,
    }
}

async fn spawn_s2s_lag_diagnostic_cluster() -> ConvergenceCluster {
    let node_ids: Vec<u16> = (1..=S2S_LAG_DIAGNOSTIC_NODE_COUNT).collect();
    let pki = Arc::new(mint_pki(&node_ids));
    let mut ports = Vec::with_capacity(node_ids.len());
    for _ in &node_ids {
        ports.push(pick_free_port().await);
    }

    let mut servers = Vec::with_capacity(node_ids.len());
    for (idx, &node_id) in node_ids.iter().enumerate() {
        let chaos = LinkChaos::new();
        let mut opts = TestServerOpts::default();
        opts.max_users = (S2S_LAG_DIAGNOSTIC_CLIENTS_ON_NODE + 32) as u64;
        opts.s2s_inbound_chaos = Some(chaos);
        let mut s2s = S2sConfig {
            enabled: true,
            tcp_listen: vec![loopback(ports[idx])],
            seed_addresses: Vec::new(),
            ..S2sConfig::default()
        };
        s2s.overlay.hello_interval_ms = CONVERGENCE_HELLO_INTERVAL_MS;
        s2s.overlay.hello_dead_interval_ms = S2S_LAG_DIAGNOSTIC_HELLO_DEAD_MS;
        s2s.overlay.lsa_max_age_ms = S2S_LAG_DIAGNOSTIC_LSA_MAX_AGE_MS;
        s2s.overlay.lsa_flood_pacing_interval_ms = 50;
        s2s.overlay.cost_rerun_min_interval_ms = 50;
        s2s.transport
            .set_outbound_capacity_for_test(S2S_LAG_DIAGNOSTIC_OUTBOUND_CAPACITY);
        servers.push(
            spawn_s2s_test_server_with_config(opts, Arc::clone(&pki), node_id, idx, s2s).await,
        );
    }
    for server in &servers {
        wait_for_s2s_runtime(server).await;
    }
    ConvergenceCluster {
        servers,
        s2s_ports: ports,
    }
}

async fn wait_for_convergence_cluster(cluster: &ConvergenceCluster) {
    let refs = cluster
        .servers
        .iter()
        .enumerate()
        .map(|(idx, server)| (server, (idx + 1) as u16))
        .collect::<Vec<_>>();
    wait_for_s2s_cluster(&refs).await;
}

async fn wait_for_s2s_runtime(server: &TestServer) {
    let ready = wait_until(S2S_DEADLINE, || {
        let mgr = server.server.s2s_manager();
        mgr.transport().is_some()
            && mgr.overlay().is_some()
            && mgr.application().is_some()
            && mgr.replications().is_some()
    })
    .await;

    assert!(ready, "S2S runtime did not start in time");
}

async fn wait_for_s2s_voice_send_ready(server: &TestServer, peers: &[u16]) {
    let ready = wait_until(S2S_DEADLINE, || {
        let manager = server.server.s2s_manager();
        let Some(overlay) = manager.overlay() else {
            return false;
        };
        let Some(transport) = manager.transport() else {
            return false;
        };
        peers.iter().all(|peer| {
            overlay
                .route_to_with_metric(
                    *peer,
                    ServiceLevel::BestEffort,
                    shitspeak_s2s::overlay::RoutingMetric::ConversationalQuality,
                )
                .and_then(|next_hop| {
                    transport.best_send_queue_pressure(
                        next_hop,
                        ServiceLevel::BestEffort,
                        shitspeak_s2s_transport::RoutingMetric::ConversationalQuality,
                        MessageClass::HighPriority,
                        SendOptions::default().expire_after(Duration::from_millis(250)),
                    )
                })
                .is_some()
        })
    })
    .await;

    assert!(ready, "S2S voice transport did not become send-ready");
}

async fn wait_for_s2s_direct_voice_send_ready(server: &TestServer, peers: &[u16]) {
    let ready = wait_until(S2S_DEADLINE, || {
        let Some(transport) = server.server.s2s_manager().transport() else {
            return false;
        };
        peers.iter().all(|peer| {
            transport
                .best_send_queue_pressure(
                    *peer,
                    ServiceLevel::BestEffort,
                    shitspeak_s2s_transport::RoutingMetric::ConversationalQuality,
                    MessageClass::HighPriority,
                    SendOptions::default().expire_after(Duration::from_millis(250)),
                )
                .is_some()
        })
    })
    .await;

    assert!(
        ready,
        "S2S direct voice transport did not become send-ready"
    );
}

async fn add_s2s_peer_address(server: &TestServer, node_id: u16, port: u16) {
    let transport = server
        .server
        .s2s_manager()
        .transport()
        .expect("s2s transport should be running");
    transport
        .add_address(
            node_id,
            PeerAddress::new(loopback(port), TransportKind::Tcp),
        )
        .await;
}

fn convergence_users_for_node(node_id: u16) -> usize {
    if std::env::var_os("SHITSPEAK_FULL_CONVERGENCE_LOAD").is_some() || node_id == 6 {
        CONVERGENCE_USERS_PER_NODE
    } else {
        CONVERGENCE_LIGHT_USERS_PER_NODE
    }
}

async fn add_synthetic_published_users(server: &TestServer, node_id: u16) -> Vec<u32> {
    let user_count = convergence_users_for_node(node_id);
    let mut sessions = Vec::with_capacity(user_count);
    for idx in 0..user_count {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let octet = ((idx % 250) + 1) as u8;
        let peer = std::net::SocketAddr::from(([10, node_id as u8, 0, octet], 20_000 + idx as u16));
        let local = std::net::SocketAddr::from(([127, 0, 0, 1], 30_000 + idx as u16));
        let client = server
            .server
            .get_clients()
            .allocate_web_client(peer.ip(), peer, local, tx)
            .await;
        {
            let mut gs = client.write_global_state_direct();
            gs.set_user_id(Some(u32::from(node_id) * 100_000 + idx as u32));
            gs.set_display_name(Some(format!("node{node_id}-user{idx:03}")));
            gs.set_current_channel_id(0);
        }
        let session = client.get_session_id();
        client.set_authenticated(true);
        server.server.get_clients().publish_client(session).await;
        sessions.push(u32::from(session));
    }
    sessions
}

async fn add_synthetic_published_user_count(
    server: &TestServer,
    node_id: u16,
    user_count: usize,
) -> Vec<u32> {
    let mut sessions = Vec::with_capacity(user_count);
    for idx in 0..user_count {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let octet = ((idx % 250) + 1) as u8;
        let peer = std::net::SocketAddr::from(([10, node_id as u8, 1, octet], 21_000 + idx as u16));
        let local = std::net::SocketAddr::from(([127, 0, 0, 1], 31_000 + idx as u16));
        let client = server
            .server
            .get_clients()
            .allocate_web_client(peer.ip(), peer, local, tx)
            .await;
        {
            let mut gs = client.write_global_state_direct();
            gs.set_user_id(Some(u32::from(node_id) * 200_000 + idx as u32));
            gs.set_display_name(Some(format!("lag-node{node_id}-user{idx:03}")));
            gs.set_current_channel_id(0);
        }
        let session = client.get_session_id();
        client.set_authenticated(true);
        server.server.get_clients().publish_client(session).await;
        sessions.push(u32::from(session));
    }
    sessions
}

async fn wait_for_observer_to_know_users(
    observer: &TestClient,
    sessions: &[u32],
    deadline: Duration,
) -> bool {
    let mut remaining = sessions
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    for state in &observer.initial_user_states {
        if let Some(session) = state.session {
            remaining.remove(&session);
        }
    }
    let until = Instant::now() + deadline;
    while !remaining.is_empty() && Instant::now() < until {
        let Some(message) = observer.recv(Duration::from_millis(250)).await else {
            continue;
        };
        if let Message::UserState(state) = message {
            if let Some(session) = state.session {
                remaining.remove(&session);
            }
        }
    }
    remaining.is_empty()
}

async fn wait_for_observer_sessions_in_channel(
    observer: &TestClient,
    sessions: &[u32],
    channel_id: u32,
    deadline: Duration,
) -> Option<Duration> {
    let started = Instant::now();
    let mut remaining = sessions
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    for state in &observer.initial_user_states {
        if state.channel_id == Some(channel_id) {
            if let Some(session) = state.session {
                remaining.remove(&session);
            }
        }
    }
    while !remaining.is_empty() && started.elapsed() < deadline {
        let Some(message) = observer.recv(Duration::from_millis(250)).await else {
            continue;
        };
        if let Message::UserState(state) = message {
            if state.channel_id == Some(channel_id) {
                if let Some(session) = state.session {
                    remaining.remove(&session);
                }
            }
        }
    }
    remaining.is_empty().then(|| started.elapsed())
}

async fn wait_for_servers_to_track_users(
    servers: &[TestServer],
    sessions_by_node: &[Vec<u32>],
    deadline: Duration,
) -> bool {
    wait_until(deadline, || {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            servers.iter().all(|server| {
                sessions_by_node.iter().flatten().all(|&session| {
                    handle
                        .block_on(
                            server
                                .server
                                .get_clients()
                                .get_client(ClientSessionIdentifier::from(session)),
                        )
                        .is_some()
                })
            })
        })
    })
    .await
}

async fn wait_for_server_sessions_in_channel(
    server: &TestServer,
    sessions: &[u32],
    channel_id: u32,
    deadline: Duration,
) -> Option<Duration> {
    let started = Instant::now();
    let reached = wait_until(deadline, || {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            sessions.iter().copied().all(|session| {
                handle
                    .block_on(
                        server
                            .server
                            .get_clients()
                            .get_client(ClientSessionIdentifier::from(session)),
                    )
                    .is_some_and(|client| client.get_current_channel_id() == channel_id)
            })
        })
    })
    .await;
    reached.then(|| started.elapsed())
}

async fn server_session_channel_summary(
    server: &TestServer,
    sessions: &[u32],
    channel_id: u32,
) -> (
    usize,
    usize,
    Vec<u32>,
    Option<u64>,
    std::collections::HashMap<u16, u64>,
) {
    let mut known = 0usize;
    let mut moved = 0usize;
    let mut not_moved = Vec::new();
    for &session in sessions {
        if let Some(client) = server
            .server
            .get_clients()
            .get_client(ClientSessionIdentifier::from(session))
            .await
        {
            known += 1;
            if client.get_current_channel_id() == channel_id {
                moved += 1;
            } else {
                not_moved.push(session);
            }
        }
    }
    let (_, versions) = server.server.get_clients().snapshot_with_versions().await;
    let node1_version = versions.get(&1).copied();
    (known, moved, not_moved, node1_version, versions)
}

async fn move_synthetic_clients_to_channel(
    server: &TestServer,
    sessions: &[u32],
    channel_id: u32,
) -> Duration {
    let started = Instant::now();
    let channel_version = server.server.get_channels().current_version();
    for &session in sessions {
        let session_id = ClientSessionIdentifier::from(session);
        let client = server
            .server
            .get_clients()
            .get_client(session_id)
            .await
            .expect("synthetic local client");
        client.set_current_channel_id(
            channel_id,
            server.server.get_clients().as_ref(),
            channel_version,
        );
    }
    started.elapsed()
}

fn apply_uniform_s2s_latency(cluster: &ConvergenceCluster, latency: Duration) {
    for (node_idx, server) in cluster.servers.iter().enumerate() {
        let Some(chaos) = server.s2s_inbound_chaos() else {
            continue;
        };
        let inbound_node = (node_idx + 1) as u16;
        for peer in 1..=cluster.servers.len() as u16 {
            if peer == inbound_node {
                continue;
            }
            chaos.add_latency(peer, latency);
        }
    }
}

fn apply_slow_s2s_links_from_node(
    cluster: &ConvergenceCluster,
    sender_node: u16,
    slow_receivers: &[u16],
    latency: Duration,
) {
    for &receiver in slow_receivers {
        let Some(server) = cluster.servers.get(usize::from(receiver - 1)) else {
            continue;
        };
        if let Some(chaos) = server.s2s_inbound_chaos() {
            chaos.add_latency(sender_node, latency);
        }
    }
}

async fn wait_for_user_removes(
    observer: &TestClient,
    sessions: &[u32],
    deadline: Duration,
) -> Option<Duration> {
    let started = Instant::now();
    let mut remaining = sessions
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    while !remaining.is_empty() && started.elapsed() < deadline {
        let Some(message) = observer.recv(Duration::from_millis(250)).await else {
            continue;
        };
        if let Message::UserRemove(remove) = message {
            remaining.remove(&remove.session);
        }
    }
    remaining.is_empty().then(|| started.elapsed())
}

async fn wait_for_user_state_update(
    observer: &TestClient,
    session: u32,
    deadline: Duration,
    predicate: impl Fn(&crate::mumble_proto::UserState) -> bool,
) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < deadline {
        let Some(message) = observer.recv(Duration::from_millis(250)).await else {
            continue;
        };
        if let Message::UserState(state) = message {
            if state.session == Some(session) && predicate(&state) {
                return Some(started.elapsed());
            }
        }
    }
    None
}

async fn observer_sees_user_churn(
    observer: &TestClient,
    sessions: &[u32],
    watch_for: Duration,
) -> bool {
    let watched = sessions
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let started = Instant::now();
    while started.elapsed() < watch_for {
        let remaining = watch_for.saturating_sub(started.elapsed());
        let Some(message) = observer
            .recv(remaining.min(Duration::from_millis(250)))
            .await
        else {
            continue;
        };
        match message {
            Message::UserState(state) => {
                if state
                    .session
                    .is_some_and(|session| watched.contains(&session))
                {
                    return true;
                }
            }
            Message::UserRemove(remove) => {
                if watched.contains(&remove.session) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn register_pair_users(a: &TestServer, b: &TestServer) {
    a.authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    b.authenticator.register_user("bob", None, Some(2), vec![]);
}

async fn wait_for_server_to_track_client(server: &TestServer, session: ClientSessionIdentifier) {
    let tracked = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(server.server.get_clients().get_client(session))
                .is_some()
        })
    })
    .await;
    assert!(tracked, "server should track client {session:?}");
}

async fn client_sees_user_state(
    client: &TestClient,
    session: ClientSessionIdentifier,
    name: &str,
) -> bool {
    let session = u32::from(session);
    client
        .initial_user_states
        .iter()
        .any(|us| us.session == Some(session) && user_state_name_matches(us.name.as_deref(), name))
        || client
            .recv_until(
                |m| {
                    matches!(m, Message::UserState(us)
                        if us.session == Some(session) && user_state_name_matches(us.name.as_deref(), name))
                },
                S2S_DEADLINE,
            )
            .await
            .is_some()
}

fn user_state_name_matches(actual: Option<&str>, expected: &str) -> bool {
    actual.is_some_and(|actual| {
        actual == expected
            || actual
                .strip_prefix(expected)
                .is_some_and(|suffix| suffix.starts_with(" [n") && suffix.ends_with(']'))
    })
}

fn opus_frame(payload: &AudioPayload) -> &[u8] {
    match payload {
        AudioPayload::Opus(opus) => &opus.frame,
        other => panic!("expected Opus payload, got {other:?}"),
    }
}

fn s2s_voice_target(slot: u32, targets: Vec<VoiceTargetEntry>) -> VoiceTarget {
    VoiceTarget {
        id: Some(slot),
        targets,
    }
}

fn s2s_voice_target_channel(
    channel_id: u32,
    children: bool,
    links: bool,
    group: Option<&str>,
) -> VoiceTargetEntry {
    VoiceTargetEntry {
        session: Vec::new(),
        channel_id: Some(channel_id),
        group: group.map(str::to_owned),
        links: Some(links),
        children: Some(children),
    }
}

struct S2SVoiceStreamDelivery {
    first_at: Instant,
    last_at: Instant,
    received_at: Vec<(usize, Instant)>,
    max_frame_gap: Duration,
}

struct S2SRouteResourceSample {
    total_before: crate::voice::metrics::VoiceRouteMetricSnapshot,
    resolution_before: crate::voice::metrics::VoiceRouteMetricSnapshot,
}

impl S2SRouteResourceSample {
    fn capture_target() -> Self {
        Self {
            total_before: route_metric_snapshot(VoiceRouteSource::S2s, VoiceRouteKind::Target),
            resolution_before: route_resolution_metric_snapshot(
                VoiceRouteSource::S2s,
                VoiceRouteKind::Target,
            ),
        }
    }

    fn finish(self) -> S2SRouteResourceMeasurement {
        let total = route_metric_snapshot(VoiceRouteSource::S2s, VoiceRouteKind::Target)
            .saturating_sub(self.total_before);
        let resolution =
            route_resolution_metric_snapshot(VoiceRouteSource::S2s, VoiceRouteKind::Target)
                .saturating_sub(self.resolution_before);
        S2SRouteResourceMeasurement { total, resolution }
    }
}

struct S2SRouteResourceMeasurement {
    total: crate::voice::metrics::VoiceRouteMetricSnapshot,
    resolution: crate::voice::metrics::VoiceRouteMetricSnapshot,
}

impl S2SRouteResourceMeasurement {
    fn frames(&self) -> u64 {
        self.total.frames()
    }

    fn total_duration(&self) -> Duration {
        self.total.duration()
    }

    fn resolution_duration(&self) -> Duration {
        self.resolution.duration()
    }
}

fn s2s_prometheus_total(server: &TestServer, metric: &str, labels: &[(&str, &str)]) -> f64 {
    server
        .server
        .s2s_manager()
        .prometheus_samples()
        .unwrap_or_default()
        .into_iter()
        .filter(|sample| {
            sample.name() == metric
                && labels.iter().all(|(key, value)| {
                    sample.labels().iter().any(|(sample_key, sample_value)| {
                        sample_key == key && sample_value == value
                    })
                })
        })
        .map(|sample| sample.value())
        .sum()
}

async fn wait_for_s2s_tree_voice_forwarding(source: &TestServer, speaker: &TestClient, slot: u32) {
    const REQUIRED_TREE_FORWARDS: usize = 3;
    const MAX_ACTIVATION_PROBES: u64 = 100;

    let original_before = s2s_prometheus_total(
        source,
        "shitspeak_s2s_distribution_events_total",
        &[("profile", "voice_realtime"), ("event", "original_forward")],
    );
    for attempt in 0..MAX_ACTIVATION_PROBES {
        speaker
            .send_voice_tcp_terminator(
                slot,
                70_000 + attempt,
                Bytes::from(format!("s2s-tree-warmup-{attempt}").into_bytes()),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let originals = s2s_prometheus_total(
            source,
            "shitspeak_s2s_distribution_events_total",
            &[("profile", "voice_realtime"), ("event", "original_forward")],
        );
        if (originals - original_before).max(0.0) >= REQUIRED_TREE_FORWARDS as f64 {
            return;
        }
    }

    panic!(
        "tree delivery did not observe {REQUIRED_TREE_FORWARDS} active forwards after {MAX_ACTIVATION_PROBES} activation probes"
    );
}

async fn wait_for_s2s_tree_voice_forwarding_between(
    speaker: &TestClient,
    slot: u32,
    source_node: u16,
    destination_node: u16,
) {
    const REQUIRED_CONSECUTIVE_TREE_FORWARDS: usize = 3;
    const MAX_ACTIVATION_PROBES: u64 = 100;

    let mut previous_originals = S2SDebugVoiceIoSnapshot::capture_between(
        "application.voice.tree.original",
        source_node,
        destination_node,
    )
    .sent_count;
    let mut consecutive_tree_forwards = 0;
    for attempt in 0..MAX_ACTIVATION_PROBES {
        speaker
            .send_voice_tcp_terminator(
                slot,
                70_000 + attempt,
                Bytes::from(format!("s2s-tree-warmup-{attempt}").into_bytes()),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let originals = S2SDebugVoiceIoSnapshot::capture_between(
            "application.voice.tree.original",
            source_node,
            destination_node,
        )
        .sent_count;
        if originals > previous_originals {
            consecutive_tree_forwards += 1;
        } else {
            consecutive_tree_forwards = 0;
        }
        previous_originals = originals;
        if consecutive_tree_forwards >= REQUIRED_CONSECUTIVE_TREE_FORWARDS {
            return;
        }
    }

    panic!(
        "tree delivery did not sustain {REQUIRED_CONSECUTIVE_TREE_FORWARDS} direct forwards from node {source_node} to node {destination_node} after {MAX_ACTIVATION_PROBES} activation probes"
    );
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
struct S2SDebugVoiceIoSnapshot {
    #[serde(default)]
    source: u16,
    #[serde(default)]
    destination: u16,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    sent_bytes: u64,
    #[serde(default)]
    recv_bytes: u64,
    #[serde(default)]
    total_bytes: u64,
    #[serde(default)]
    sent_count: u64,
    #[serde(default)]
    recv_count: u64,
    #[serde(default)]
    total_count: u64,
}

impl S2SDebugVoiceIoSnapshot {
    fn capture(kind: &str) -> Self {
        Self::capture_matching(kind, |_| true)
    }

    fn capture_between(kind: &str, source: u16, destination: u16) -> Self {
        let mut snapshot = Self::capture_matching(kind, |row| {
            row.source == source && row.destination == destination
        });
        snapshot.source = source;
        snapshot.destination = destination;
        snapshot
    }

    fn capture_matching(kind: &str, filter: impl Fn(&Self) -> bool) -> Self {
        shitspeak_s2s::debug_io::snapshot()
            .into_iter()
            .filter_map(|row| {
                serde_json::to_value(row)
                    .ok()
                    .and_then(|value| serde_json::from_value::<Self>(value).ok())
            })
            .filter(|row| row.kind == kind && filter(row))
            .fold(
                Self {
                    kind: kind.to_owned(),
                    ..Self::default()
                },
                |mut total, row| {
                    total.sent_bytes = total.sent_bytes.saturating_add(row.sent_bytes);
                    total.recv_bytes = total.recv_bytes.saturating_add(row.recv_bytes);
                    total.total_bytes = total.total_bytes.saturating_add(row.total_bytes);
                    total.sent_count = total.sent_count.saturating_add(row.sent_count);
                    total.recv_count = total.recv_count.saturating_add(row.recv_count);
                    total.total_count = total.total_count.saturating_add(row.total_count);
                    total
                },
            )
    }

    fn saturating_sub(&self, before: &Self) -> Self {
        Self {
            source: self.source,
            destination: self.destination,
            kind: self.kind.clone(),
            sent_bytes: self.sent_bytes.saturating_sub(before.sent_bytes),
            recv_bytes: self.recv_bytes.saturating_sub(before.recv_bytes),
            total_bytes: self.total_bytes.saturating_sub(before.total_bytes),
            sent_count: self.sent_count.saturating_sub(before.sent_count),
            recv_count: self.recv_count.saturating_sub(before.recv_count),
            total_count: self.total_count.saturating_sub(before.total_count),
        }
    }

    fn saturating_add(mut self, other: &Self) -> Self {
        self.sent_bytes = self.sent_bytes.saturating_add(other.sent_bytes);
        self.recv_bytes = self.recv_bytes.saturating_add(other.recv_bytes);
        self.total_bytes = self.total_bytes.saturating_add(other.total_bytes);
        self.sent_count = self.sent_count.saturating_add(other.sent_count);
        self.recv_count = self.recv_count.saturating_add(other.recv_count);
        self.total_count = self.total_count.saturating_add(other.total_count);
        self
    }
}

fn s2s_shout_route_busy_cores(route_duration: Duration, wall: Duration) -> Option<f64> {
    let wall_secs = wall.as_secs_f64();
    if wall_secs <= f64::EPSILON {
        return None;
    }
    Some(route_duration.as_secs_f64() / wall_secs)
}

fn s2s_shout_voice_segment(base_frame: u64) -> Vec<(u64, Bytes)> {
    (0..S2S_SHOUT_FRAMES)
        .map(|offset| {
            let frame_number = base_frame + offset as u64;
            let payload = Bytes::from(format!("s2s-shout-opus-frame-{frame_number}").into_bytes());
            (frame_number, payload)
        })
        .collect()
}

fn s2s_shout_segment_send_span(frames: &[(u64, Bytes)]) -> Duration {
    let intervals = frames.len().saturating_sub(1) as u32;
    S2S_SHOUT_FRAME_INTERVAL * intervals
}

async fn send_s2s_shout_voice_segment(
    alice: &TestClient,
    slot: u32,
    frames: &[(u64, Bytes)],
) -> Vec<Instant> {
    let mut sent_at = Vec::with_capacity(frames.len());
    for (idx, (frame_number, payload)) in frames.iter().enumerate() {
        sent_at.push(Instant::now());
        if idx + 1 == frames.len() {
            alice
                .send_voice_tcp_terminator(slot, *frame_number, payload.clone())
                .await;
        } else {
            alice
                .send_voice_tcp(slot, *frame_number, payload.clone())
                .await;
            tokio::time::sleep(S2S_SHOUT_FRAME_INTERVAL).await;
        }
    }
    sent_at
}

async fn wait_for_s2s_root_shout_delivery(
    speaker: &TestClient,
    listeners: &[&TestClient],
    slot: u32,
) {
    const REQUIRED_CONSECUTIVE_MARKERS: usize = 3;
    const MARKER_ATTEMPTS: u64 = 20;

    let mut consecutive_markers = 0;

    for attempt in 0..MARKER_ATTEMPTS {
        for listener in listeners {
            listener.drain_now().await;
        }
        let frames = (0..4_u64)
            .map(|offset| {
                let frame_number = 71_000 + attempt * 10 + offset;
                (
                    frame_number,
                    Bytes::from(format!("s2s-root-tree-warmup-{frame_number}").into_bytes()),
                )
            })
            .collect::<Vec<_>>();
        let send_task = send_s2s_shout_voice_segment(speaker, slot, &frames);
        let receive_task = async {
            join_all(listeners.iter().enumerate().map(|(index, listener)| {
                try_receive_s2s_shout_stream(listener, speaker, index, &frames)
            }))
            .await
        };
        let (_sent_at, deliveries) = tokio::join!(send_task, receive_task);
        if deliveries.iter().all(Option::is_some) {
            consecutive_markers += 1;
            if consecutive_markers >= REQUIRED_CONSECUTIVE_MARKERS {
                return;
            }
        } else {
            consecutive_markers = 0;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!(
        "root-shout delivery did not complete {REQUIRED_CONSECUTIVE_MARKERS} consecutive marker talkspurts for every listener after {MARKER_ATTEMPTS} attempts"
    );
}

async fn try_receive_s2s_shout_stream(
    client: &TestClient,
    sender: &TestClient,
    _client_index: usize,
    frames: &[(u64, Bytes)],
) -> Option<S2SVoiceStreamDelivery> {
    let mut first_at = None;
    let mut last_at = None;
    let mut previous_receive_at = None;
    let mut received_times = Vec::with_capacity(frames.len());
    let mut max_frame_gap = Duration::ZERO;

    for (offset, (frame_number, payload)) in frames.iter().enumerate() {
        let audio = client
            .recv_voice_tcp(S2S_SHOUT_FRAME_LATENCY_BUDGET)
            .await?;
        let received_at = Instant::now();
        if audio.sender_session != Some(sender.server_session)
            || audio.frame_number != *frame_number
            || opus_frame(&audio.audio_payload) != payload.as_ref()
        {
            return None;
        }
        if first_at.is_none() {
            first_at = Some(received_at);
        }
        if let Some(previous) = previous_receive_at {
            max_frame_gap = max_frame_gap.max(received_at.duration_since(previous));
        }
        previous_receive_at = Some(received_at);
        received_times.push((offset, received_at));
        last_at = Some(received_at);
    }

    Some(S2SVoiceStreamDelivery {
        first_at: first_at.expect("marker stream should contain at least one frame"),
        last_at: last_at.expect("marker stream should contain at least one frame"),
        received_at: received_times,
        max_frame_gap,
    })
}

async fn receive_s2s_shout_stream(
    client: &TestClient,
    sender: &TestClient,
    client_index: usize,
    frames: &[(u64, Bytes)],
) -> S2SVoiceStreamDelivery {
    let mut first_at = None;
    let mut last_at = None;
    let mut previous_receive_at = None;
    let mut received_times = Vec::with_capacity(frames.len());
    let mut max_frame_gap = Duration::from_millis(0);

    for (offset, (frame_number, payload)) in frames.iter().enumerate() {
        let audio = client
            .recv_voice_tcp(S2S_SHOUT_FRAME_LATENCY_BUDGET)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "remote listener {client_index} should receive cross-node shout frame {frame_number}"
                )
            });
        let received_at = Instant::now();
        if first_at.is_none() {
            first_at = Some(received_at);
        }
        if let Some(previous) = previous_receive_at {
            max_frame_gap = max_frame_gap.max(received_at.duration_since(previous));
        }
        previous_receive_at = Some(received_at);
        received_times.push((offset, received_at));

        assert_eq!(
            audio.sender_session,
            Some(sender.server_session),
            "remote listener {client_index} saw the wrong sender for frame {frame_number}"
        );
        assert_eq!(
            audio.frame_number, *frame_number,
            "remote listener {client_index} received non-contiguous cross-node shout audio"
        );
        assert_eq!(
            opus_frame(&audio.audio_payload),
            payload.as_ref(),
            "remote listener {client_index} received corrupted cross-node shout payload"
        );
        last_at = Some(received_at);
    }

    S2SVoiceStreamDelivery {
        first_at: first_at.expect("voice stream should contain at least one frame"),
        last_at: last_at.expect("voice stream should contain at least one frame"),
        received_at: received_times,
        max_frame_gap,
    }
}

async fn receive_s2s_shout_stream_udp(
    client: &TestClient,
    sender: &TestClient,
    client_index: usize,
    frames: &[(u64, Bytes)],
) -> S2SVoiceStreamDelivery {
    let mut first_at = None;
    let mut last_at = None;
    let mut previous_receive_at = None;
    let mut received_times = Vec::with_capacity(frames.len());
    let mut max_frame_gap = Duration::ZERO;

    for (offset, (frame_number, payload)) in frames.iter().enumerate() {
        let audio = client
            .recv_voice_udp(S2S_SHOUT_FRAME_LATENCY_BUDGET)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "remote UDP listener {client_index} should receive cross-node shout frame {frame_number}"
                )
            });
        let received_at = Instant::now();
        if first_at.is_none() {
            first_at = Some(received_at);
        }
        if let Some(previous) = previous_receive_at {
            max_frame_gap = max_frame_gap.max(received_at.duration_since(previous));
        }
        previous_receive_at = Some(received_at);
        received_times.push((offset, received_at));

        assert_eq!(
            audio.sender_session,
            Some(sender.server_session),
            "remote UDP listener {client_index} saw the wrong sender for frame {frame_number}"
        );
        assert_eq!(
            audio.frame_number, *frame_number,
            "remote UDP listener {client_index} received non-contiguous cross-node shout audio"
        );
        assert_eq!(
            opus_frame(&audio.audio_payload),
            payload.as_ref(),
            "remote UDP listener {client_index} received corrupted cross-node shout payload"
        );
        last_at = Some(received_at);
    }

    S2SVoiceStreamDelivery {
        first_at: first_at.expect("voice UDP stream should contain at least one frame"),
        last_at: last_at.expect("voice UDP stream should contain at least one frame"),
        received_at: received_times,
        max_frame_gap,
    }
}

async fn receive_s2s_shout_stream_with_loss_budget(
    client: &TestClient,
    sender: &TestClient,
    client_index: usize,
    frames: &[(u64, Bytes)],
) -> S2SVoiceStreamDelivery {
    let allowed_loss = frames
        .len()
        .saturating_mul(S2S_SHOUT_LOSS_BUDGET_PERCENT)
        .div_ceil(100);
    let mut first_at = None;
    let mut last_at = None;
    let mut previous_receive_at = None;
    let mut previous_offset = None;
    let mut received_times = Vec::with_capacity(frames.len());
    let mut max_frame_gap = Duration::ZERO;

    loop {
        let Some(audio) = client.recv_voice_tcp(S2S_SHOUT_FRAME_LATENCY_BUDGET).await else {
            break;
        };
        let received_at = Instant::now();
        let offset = frames
            .binary_search_by_key(&audio.frame_number, |(frame_number, _)| *frame_number)
            .unwrap_or_else(|_| {
                panic!(
                    "remote listener {client_index} received unexpected shout frame {}",
                    audio.frame_number
                )
            });

        assert_eq!(
            audio.sender_session,
            Some(sender.server_session),
            "remote listener {client_index} saw the wrong sender for frame {}",
            audio.frame_number
        );
        assert!(
            previous_offset.is_none_or(|previous| offset > previous),
            "remote listener {client_index} received reordered or duplicate shout frame {}",
            audio.frame_number
        );
        assert_eq!(
            opus_frame(&audio.audio_payload),
            frames[offset].1.as_ref(),
            "remote listener {client_index} received corrupted shout payload"
        );

        if first_at.is_none() {
            first_at = Some(received_at);
        }
        if let Some(previous) = previous_receive_at {
            max_frame_gap = max_frame_gap.max(received_at.duration_since(previous));
        }
        previous_receive_at = Some(received_at);
        previous_offset = Some(offset);
        last_at = Some(received_at);
        received_times.push((offset, received_at));

        if offset + 1 == frames.len() {
            break;
        }
    }

    let missing_frames = frames
        .iter()
        .enumerate()
        .filter_map(|(offset, (frame_number, _))| {
            (!received_times
                .iter()
                .any(|(received_offset, _)| *received_offset == offset))
            .then_some(*frame_number)
        })
        .collect::<Vec<_>>();
    assert!(
        missing_frames.len() <= allowed_loss,
        "remote listener {client_index} lost {} of {} shout frames; budget is {allowed_loss}; missing={missing_frames:?}",
        missing_frames.len(),
        frames.len()
    );

    S2SVoiceStreamDelivery {
        first_at: first_at.expect("voice stream should contain at least one frame"),
        last_at: last_at.expect("voice stream should contain at least one frame"),
        received_at: received_times,
        max_frame_gap,
    }
}

async fn receive_s2s_shout_stream_udp_with_loss_budget(
    client: &TestClient,
    sender: &TestClient,
    client_index: usize,
    frames: &[(u64, Bytes)],
) -> S2SVoiceStreamDelivery {
    let allowed_loss = frames
        .len()
        .saturating_mul(S2S_SHOUT_LOSS_BUDGET_PERCENT)
        .div_ceil(100);
    let mut first_at = None;
    let mut last_at = None;
    let mut previous_receive_at = None;
    let mut previous_offset = None;
    let mut received_times = Vec::with_capacity(frames.len());
    let mut max_frame_gap = Duration::ZERO;

    loop {
        let Some(audio) = client.recv_voice_udp(S2S_SHOUT_FRAME_LATENCY_BUDGET).await else {
            break;
        };
        let received_at = Instant::now();
        let offset = frames
            .binary_search_by_key(&audio.frame_number, |(frame_number, _)| *frame_number)
            .unwrap_or_else(|_| {
                panic!(
                    "remote UDP listener {client_index} received unexpected shout frame {}",
                    audio.frame_number
                )
            });

        assert_eq!(
            audio.sender_session,
            Some(sender.server_session),
            "remote UDP listener {client_index} saw the wrong sender for frame {}",
            audio.frame_number
        );
        assert!(
            previous_offset.is_none_or(|previous| offset > previous),
            "remote UDP listener {client_index} received reordered or duplicate shout frame {}",
            audio.frame_number
        );
        assert_eq!(
            opus_frame(&audio.audio_payload),
            frames[offset].1.as_ref(),
            "remote UDP listener {client_index} received corrupted shout payload"
        );

        if first_at.is_none() {
            first_at = Some(received_at);
        }
        if let Some(previous) = previous_receive_at {
            max_frame_gap = max_frame_gap.max(received_at.duration_since(previous));
        }
        previous_receive_at = Some(received_at);
        previous_offset = Some(offset);
        last_at = Some(received_at);
        received_times.push((offset, received_at));

        if offset + 1 == frames.len() {
            break;
        }
    }

    let missing_frames = frames
        .iter()
        .enumerate()
        .filter_map(|(offset, (frame_number, _))| {
            (!received_times
                .iter()
                .any(|(received_offset, _)| *received_offset == offset))
            .then_some(*frame_number)
        })
        .collect::<Vec<_>>();
    assert!(
        missing_frames.len() <= allowed_loss,
        "remote UDP listener {client_index} lost {} of {} shout frames; budget is {allowed_loss}; missing={missing_frames:?}",
        missing_frames.len(),
        frames.len()
    );

    S2SVoiceStreamDelivery {
        first_at: first_at.expect("voice UDP stream should contain at least one frame"),
        last_at: last_at.expect("voice UDP stream should contain at least one frame"),
        received_at: received_times,
        max_frame_gap,
    }
}

fn max_s2s_shout_frame_latency(
    deliveries: &[S2SVoiceStreamDelivery],
    sent_at: &[Instant],
) -> Duration {
    deliveries
        .iter()
        .flat_map(|delivery| delivery.received_at.iter())
        .map(|(offset, received_at)| received_at.saturating_duration_since(sent_at[*offset]))
        .max()
        .unwrap_or_default()
}

async fn wait_for_s2s_voice_target_installed(
    server: &crate::integration_tests::harness::TestServer,
    client: &TestClient,
    slot: u32,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let sender = server
            .server
            .get_clients()
            .get_client(client.server_session)
            .await
            .expect("sender should remain connected");
        if sender.voice_target(slot).is_some() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "voice target slot {slot} was not installed before cross-node shout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn create_s2s_root_shout_traffic_tree(server: &TestServer) -> Vec<u32> {
    let mut channel_ids = Vec::with_capacity(S2S_ROOT_SHOUT_TRAFFIC_CHANNELS.len());
    for &(channel_id, parent_id, name) in S2S_ROOT_SHOUT_TRAFFIC_CHANNELS {
        let result = server
            .server
            .s2s_manager()
            .propose_channel_op(
                None,
                shitspeak_state::ChannelOp::CreateChannel {
                    channel: Channel::new(channel_id, name.to_owned(), 0, 0, Some(parent_id)),
                },
            )
            .await;
        assert!(
            result.is_proposed(),
            "strict proposal for traffic channel {channel_id} ({name}, parent {parent_id}) failed: {result:?}"
        );
        channel_ids.push(channel_id);
    }
    channel_ids
}

async fn wait_for_s2s_channels_on_servers(
    servers: &[&TestServer],
    channel_ids: &[u32],
    deadline: Duration,
) {
    let started = Instant::now();
    loop {
        let mut missing = Vec::new();
        for (server_idx, server) in servers.iter().enumerate() {
            for &channel_id in channel_ids {
                if server
                    .server
                    .get_channels()
                    .get_channel(channel_id)
                    .await
                    .is_none()
                {
                    missing.push((server_idx, channel_id));
                }
            }
        }
        if missing.is_empty() {
            return;
        }
        assert!(
            started.elapsed() < deadline,
            "S2S channel replication did not converge; missing={missing:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn connect_s2s_shout_listener(
    server: &TestServer,
    username: &str,
) -> Result<TestClient, ConnectError> {
    let mut last_error = None;
    for attempt in 1..=S2S_SHOUT_CONNECT_ATTEMPTS {
        match TestClient::connect_and_authenticate_with_deadline(
            server,
            username,
            None,
            S2S_SHOUT_CONNECT_ATTEMPT_DEADLINE,
        )
        .await
        {
            Ok(client) => {
                if attempt > 1 {
                    eprintln!(
                        "s2s_shout_connect username={} recovered_on_attempt={}",
                        username, attempt
                    );
                }
                return Ok(client);
            }
            Err(error) => {
                eprintln!(
                    "s2s_shout_connect username={} attempt={} failed={:?}",
                    username, attempt, error
                );
                last_error = Some(error);
                if attempt < S2S_SHOUT_CONNECT_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or(ConnectError::NoServerSync))
}

async fn connect_s2s_shout_listeners(server: &TestServer, count: usize) -> Vec<TestClient> {
    let started = Instant::now();
    let mut pending = FuturesUnordered::new();
    for idx in 0..count {
        let username = format!("remote-listener-{idx:03}");
        pending.push(async move {
            let connected_at = Instant::now();
            let result = connect_s2s_shout_listener(server, &username).await;
            (idx, connected_at.elapsed(), result)
        });
    }

    let mut connected = Vec::with_capacity(count);
    let mut progress_tick = tokio::time::interval(Duration::from_secs(5));
    progress_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while connected.len() < count {
        tokio::select! {
            item = pending.next() => {
                let Some((idx, elapsed, client)) = item else {
                    break;
                };
                let client = client.unwrap_or_else(|err| {
                    panic!("connect remote-listener-{idx:03}: {err:?}");
                });
                connected.push((idx, client));
                if connected.len() % 50 == 0 || connected.len() == count {
                    eprintln!(
                        "s2s_shout_connect completed={} pending={} last_client={} last_ms={} elapsed_ms={}",
                        connected.len(),
                        pending.len(),
                        idx,
                        elapsed.as_millis(),
                        started.elapsed().as_millis(),
                    );
                }
            }
            _ = progress_tick.tick() => {
                let local_clients = server.server.get_clients().get_local_clients().await;
                let authenticated = local_clients.iter().filter(|client| client.is_authenticated()).count();
                let published = local_clients.iter().filter(|client| client.is_published()).count();
                eprintln!(
                    "s2s_shout_connect waiting completed={} pending={} local={} authenticated={} published={} elapsed_ms={}",
                    connected.len(),
                    pending.len(),
                    local_clients.len(),
                    authenticated,
                    published,
                    started.elapsed().as_millis(),
                );
            }
        }
    }
    assert_eq!(
        connected.len(),
        count,
        "every cross-node shout listener should authenticate"
    );
    connected.sort_by_key(|(idx, _)| *idx);
    connected.into_iter().map(|(_, client)| client).collect()
}

async fn prepare_s2s_shout_udp_listeners(server: &TestServer, listeners: &mut [TestClient]) {
    for listener in &mut *listeners {
        listener
            .open_udp()
            .await
            .expect("cross-node shout UDP listener bind");
        listener
            .udp_handshake()
            .await
            .expect("cross-node shout UDP listener handshake");
    }
    // The handshake is an encrypted ping consumed by the server's UDP
    // ingress. Allow the address bindings to become visible before routing the
    // measured talkspurt; otherwise the first frame can legitimately choose
    // the TCP fallback while the server is still learning each endpoint.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut ready = true;
        for listener in listeners.iter() {
            let client = server
                .server
                .get_clients()
                .get_client(listener.server_session)
                .await
                .expect("UDP shout listener should remain connected");
            if client.get_udp_address().is_none() || client.prefers_tcp_tunnel() {
                ready = false;
                break;
            }
        }
        if ready {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "cross-node shout UDP listener handshakes did not bind every endpoint"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Checks a cross-node `UserStats` request.
/// Expected: Alice on server A receives Bob's `UserStats` from server B with
/// the requested `stats_only` flag. The stats response shape comes from
/// `D:\mumble\src\Mumble.proto` and `D:\mumble\src\murmur\Messages.cpp::msgUserStats`;
/// shitspeak mirrors that handler in `D:\shitspeak\message.go::handleUserStatsMessage`,
/// while this crate extends delivery across S2S.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_user_stats_rpc() {
    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    wait_for_server_to_track_client(&a, bob.server_session).await;
    wait_for_server_to_track_client(&b, alice.server_session).await;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_user_stats_omits_sensitive_fields_for_non_superuser() {
    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    a.authenticator
        .register_user("alice", None, Some(1), vec![]);
    b.authenticator.register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    wait_for_server_to_track_client(&a, bob.server_session).await;
    wait_for_server_to_track_client(&b, alice.server_session).await;

    alice
        .send(
            UserStats {
                session: Some(bob.session_id),
                stats_only: Some(false),
                ..UserStats::default()
            }
            .into(),
        )
        .await;

    let msg = alice
        .recv_until(
            |m| matches!(m, Message::UserStats(us) if us.session == Some(bob.session_id)),
            CLIENT_DEADLINE,
        )
        .await;

    let Some(Message::UserStats(stats)) = msg else {
        panic!("Alice should receive Bob's cross-node stats");
    };
    assert!(stats.certificates.is_empty());
    assert_eq!(stats.address, None);
    let version = stats.version.as_ref().expect("version should be present");
    assert!(version.version_v1.is_some() || version.version_v2.is_some());
    assert_eq!(version.release, None);
    assert_eq!(version.os, None);
    assert_eq!(version.os_version, None);
    assert_eq!(stats.strong_certificate, Some(true));
}

/// Checks cross-node plugin data routing to explicitly targeted receiver sessions.
/// Expected: Bob receives Alice's `PluginDataTransmission` with the sender
/// stamped by server A and the payload preserved over S2S.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_plugin_data_transmission_routes_to_remote_recipient() {
    let _guard = s2s_network_test_guard().await;
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

/// Checks cross-node text routing to explicitly targeted receiver sessions.
/// Expected: Bob receives Alice's `TextMessage` with the sender stamped by
/// server A and the original direct-session target preserved over S2S.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_text_message_routes_to_remote_recipient() {
    let _guard = s2s_network_test_guard().await;
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
        "Server A should materialize Bob before dispatching TextMessage"
    );

    alice
        .send(
            TextMessage {
                actor: Some(999),
                session: vec![bob.session_id],
                channel_id: Vec::new(),
                tree_id: Vec::new(),
                message: "hello across nodes".to_string(),
            }
            .into(),
        )
        .await;

    let msg = bob
        .recv_until(
            |m| {
                matches!(m, Message::TextMessage(t)
                    if t.actor == Some(alice.session_id)
                        && t.session == vec![bob.session_id]
                        && t.channel_id.is_empty()
                        && t.tree_id.is_empty()
                        && t.message == "hello across nodes")
            },
            CLIENT_DEADLINE,
        )
        .await;

    assert!(
        msg.is_some(),
        "Bob should receive Alice's cross-node text message"
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
    let _guard = s2s_network_test_guard().await;
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
    let _guard = s2s_network_test_guard().await;
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

/// Checks normal speech across a linked channel on another node while the
/// S2S voice service uses targeted delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_targeted_normal_voice_routes_to_linked_channel() {
    const SOURCE_CHANNEL: u32 = 52;
    const LINKED_CHANNEL: u32 = 53;

    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_targeted_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let channels = a.server.get_channels();
    channels
        .create_channel(Channel::new(
            SOURCE_CHANNEL,
            "Normal link source".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .expect("create normal link source channel");
    channels
        .create_channel(Channel::new(
            LINKED_CHANNEL,
            "Normal linked remote".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .expect("create normal linked channel");
    channels
        .add_link(SOURCE_CHANNEL, LINKED_CHANNEL)
        .await
        .expect("link normal voice channels");

    let links_replicated = wait_until(S2S_DEADLINE, || {
        b.server
            .get_channels()
            .effective_link_group_in_server(crate::types::DEFAULT_SERVER_ID, SOURCE_CHANNEL)
            .is_some_and(|group| group.contains(&LINKED_CHANNEL))
    })
    .await;
    assert!(links_replicated, "server B should learn the channel link");

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");
    alice.move_to_channel(SOURCE_CHANNEL).await;
    bob.move_to_channel(LINKED_CHANNEL).await;

    let placements_replicated = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            let b_knows_alice = handle
                .block_on(b.server.get_clients().get_client(alice.server_session))
                .is_some_and(|client| client.get_current_channel_id() == SOURCE_CHANNEL);
            let a_knows_bob = handle
                .block_on(a.server.get_clients().get_client(bob.server_session))
                .is_some_and(|client| client.get_current_channel_id() == LINKED_CHANNEL);
            b_knows_alice && a_knows_bob
        })
    })
    .await;
    assert!(
        placements_replicated,
        "both nodes should learn the source and linked channel placements"
    );

    let linked_node_indexed = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(a.server.get_clients().voice_recipient_index_snapshot())
                .get(
                    &shitspeak_s2s::application::voice::targeted::RecipientIndexKey::new(
                        crate::types::DEFAULT_SERVER_ID,
                        LINKED_CHANNEL,
                    ),
                )
                .is_some_and(|nodes| nodes.contains(&2))
        })
    })
    .await;
    assert!(
        linked_node_indexed,
        "targeted sender index should include the linked-channel node"
    );

    let replicated_alice = b
        .server
        .get_clients()
        .get_client(alice.server_session)
        .await
        .expect("server B should retain replicated Alice");
    assert!(
        crate::client::acl::compute_permissions_for_client(
            &b.server,
            &replicated_alice,
            LINKED_CHANNEL,
        )
        .await
        .contains(shitspeak_state::ACLPermissions::Speak)
    );

    bob.drain_now().await;
    alice
        .send_voice_tcp(0, 2, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob
        .recv_voice_tcp(CLIENT_DEADLINE)
        .await
        .expect("Bob should receive normal voice through the linked channel");
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
}

/// Checks the Mumble "shout to linked channels" voice-target shape across
/// nodes. The sender targets its current channel with `links=true`, while the
/// recipient is connected to a linked channel on another server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_cross_node_voice_target_shouts_to_linked_channel() {
    const SOURCE_CHANNEL: u32 = 50;
    const LINKED_CHANNEL: u32 = 51;
    const TARGET_SLOT: u32 = 7;

    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let channels = a.server.get_channels();
    channels
        .create_channel(Channel::new(
            SOURCE_CHANNEL,
            "Link source".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .expect("create link source channel");
    channels
        .create_channel(Channel::new(
            LINKED_CHANNEL,
            "Linked remote".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .expect("create linked remote channel");
    channels
        .add_link(SOURCE_CHANNEL, LINKED_CHANNEL)
        .await
        .expect("link voice target channels");

    let links_replicated = wait_until(S2S_DEADLINE, || {
        b.server
            .get_channels()
            .effective_link_group_in_server(crate::types::DEFAULT_SERVER_ID, SOURCE_CHANNEL)
            .is_some_and(|group| group.contains(&LINKED_CHANNEL))
    })
    .await;
    assert!(links_replicated, "server B should learn the channel link");

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");
    alice.move_to_channel(SOURCE_CHANNEL).await;
    bob.move_to_channel(LINKED_CHANNEL).await;

    wait_for_server_to_track_client(&b, alice.server_session).await;
    let placements_replicated = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            let b_knows_alice = handle
                .block_on(b.server.get_clients().get_client(alice.server_session))
                .is_some_and(|client| client.get_current_channel_id() == SOURCE_CHANNEL);
            let b_knows_bob = handle
                .block_on(b.server.get_clients().get_client(bob.server_session))
                .is_some_and(|client| client.get_current_channel_id() == LINKED_CHANNEL);
            let a_knows_bob = handle
                .block_on(a.server.get_clients().get_client(bob.server_session))
                .is_some_and(|client| client.get_current_channel_id() == LINKED_CHANNEL);
            b_knows_alice && b_knows_bob && a_knows_bob
        })
    })
    .await;
    assert!(
        placements_replicated,
        "server B should learn both channel placements"
    );

    let sender_index = a
        .server
        .get_clients()
        .voice_recipient_index_snapshot()
        .await;
    let linked_nodes = sender_index
        .get(
            &shitspeak_s2s::application::voice::targeted::RecipientIndexKey::new(
                crate::types::DEFAULT_SERVER_ID,
                LINKED_CHANNEL,
            ),
        )
        .expect("sender recipient snapshot should contain the linked channel");
    assert!(
        linked_nodes.contains(&2),
        "sender recipient snapshot should route linked-channel voice to node 2"
    );

    let replicated_alice = b
        .server
        .get_clients()
        .get_client(alice.server_session)
        .await
        .expect("server B should retain replicated Alice");
    assert!(replicated_alice.is_superuser());
    let linked_permissions = crate::client::acl::compute_permissions_for_client(
        &b.server,
        &replicated_alice,
        LINKED_CHANNEL,
    )
    .await;
    assert!(linked_permissions.contains(shitspeak_state::ACLPermissions::Whisper));
    let local_bob = b
        .server
        .get_clients()
        .get_client(bob.server_session)
        .await
        .expect("server B should retain local Bob");
    assert!(
        crate::client::visibility::can_view_user(&b.server, &local_bob, &replicated_alice).await
    );

    alice
        .set_voice_target(s2s_voice_target(
            TARGET_SLOT,
            vec![s2s_voice_target_channel(SOURCE_CHANNEL, false, true, None)],
        ))
        .await;
    wait_for_s2s_voice_target_installed(&a, &alice, TARGET_SLOT).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    bob.drain_now().await;

    let route_sample = S2SRouteResourceSample::capture_target();
    alice
        .send_voice_tcp(TARGET_SLOT, 2, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob.recv_voice_tcp(CLIENT_DEADLINE).await;
    let route = route_sample.finish();
    assert_eq!(
        route.frames(),
        1,
        "server B should route the linked-channel S2S frame"
    );
    let audio = audio.expect("Bob should receive Alice's linked-channel shout");
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
}

/// Checks sustained cross-node voice-target shout delivery under a large
/// receiver batch.
/// Expected: 500 real native clients on server B receive Alice's 10-second
/// channel shout from server A as one contiguous, byte-identical stream. This
/// catches the failure mode where S2S accepts every frame but later scatters,
/// cuts, or reorders the stream before the remote TCP voice queues.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2s_cross_node_voice_target_shout_stream_is_contiguous_under_load() {
    let _guard = s2s_network_test_guard().await;
    let a_opts = TestServerOpts {
        max_users: (S2S_SHOUT_REMOTE_CLIENTS + 16) as u64,
        client_idle_timeout_secs: S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS / 1_000,
        authenticate_timeout_ms: S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS,
        auth_finalization_concurrency: S2S_SHOUT_AUTH_FINALIZATION_CONCURRENCY,
        ..TestServerOpts::default()
    };
    let b_opts = TestServerOpts {
        max_users: (S2S_SHOUT_REMOTE_CLIENTS + 16) as u64,
        client_idle_timeout_secs: S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS / 1_000,
        authenticate_timeout_ms: S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS,
        auth_finalization_concurrency: S2S_SHOUT_AUTH_FINALIZATION_CONCURRENCY,
        ..TestServerOpts::default()
    };
    let (a, b) = spawn_s2s_pair_with_opts(a_opts, b_opts).await;
    wait_for_s2s_pair(&a, &b).await;

    a.authenticator
        .register_superuser("speaker", None, Some(1), vec!["admin".into()]);
    for idx in 0..S2S_SHOUT_REMOTE_CLIENTS {
        b.authenticator.register_user(
            &format!("remote-listener-{idx:03}"),
            None,
            Some(20_000 + idx as u32),
            Vec::new(),
        );
    }

    a.server
        .get_channels()
        .create_channel(Channel::new(
            S2S_SHOUT_CHANNEL_ID,
            "Remote Voice Room".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .expect("create cross-node shout channel");
    let channel_replicated = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(b.server.get_channels().get_channel(S2S_SHOUT_CHANNEL_ID))
                .is_some()
        })
    })
    .await;
    assert!(
        channel_replicated,
        "server B should learn the shout target channel before listeners connect"
    );

    for idx in 0..S2S_SHOUT_REMOTE_CLIENTS {
        b.server
            .get_user_channel_cache()
            .remember_last_channel(&(20_000 + idx as u32).to_string(), S2S_SHOUT_CHANNEL_ID)
            .await
            .expect("remember listener channel");
    }
    let mut listeners = connect_s2s_shout_listeners(&b, S2S_SHOUT_REMOTE_CLIENTS).await;
    prepare_s2s_shout_udp_listeners(&b, &mut listeners).await;
    let listener_sessions = listeners
        .iter()
        .map(|client| client.session_id)
        .collect::<Vec<_>>();
    assert!(
        wait_for_server_sessions_in_channel(
            &b,
            &listener_sessions,
            S2S_SHOUT_CHANNEL_ID,
            S2S_DEADLINE,
        )
        .await
        .is_some(),
        "server B should place every listener in the shout channel during authentication"
    );

    let alice = TestClient::connect_and_authenticate_with_deadline(
        &a,
        "speaker",
        None,
        S2S_SHOUT_CONNECT_DEADLINE,
    )
    .await
    .expect("speaker");
    wait_for_server_to_track_client(&b, alice.server_session).await;
    alice
        .set_voice_target(s2s_voice_target(
            S2S_SHOUT_TARGET_SLOT,
            vec![s2s_voice_target_channel(
                S2S_SHOUT_CHANNEL_ID,
                false,
                false,
                None,
            )],
        ))
        .await;
    wait_for_s2s_voice_target_installed(&a, &alice, S2S_SHOUT_TARGET_SLOT).await;
    alice.drain_now().await;
    for listener in &listeners {
        listener.drain_now().await;
    }

    let frames = s2s_shout_voice_segment(50_000);
    assert!(
        s2s_shout_segment_send_span(&frames) >= S2S_SHOUT_MIN_SPEAK_SPAN,
        "cross-node shout test should continuously speak for at least {:?}",
        S2S_SHOUT_MIN_SPEAK_SPAN
    );

    let speak_start = Instant::now();
    let route_sample = S2SRouteResourceSample::capture_target();
    let send_task = async {
        let sent_at = send_s2s_shout_voice_segment(&alice, S2S_SHOUT_TARGET_SLOT, &frames).await;
        (Instant::now(), sent_at)
    };
    let receive_task =
        async {
            join_all(listeners.iter().enumerate().map(|(idx, listener)| {
                receive_s2s_shout_stream_udp(listener, &alice, idx, &frames)
            }))
            .await
        };
    let ((send_end, sent_at), deliveries) = tokio::join!(send_task, receive_task);
    let route_resources = route_sample.finish();
    let wall = speak_start.elapsed();

    let max_first_frame_latency = deliveries
        .iter()
        .map(|delivery| delivery.first_at.saturating_duration_since(sent_at[0]))
        .max()
        .unwrap_or_default();
    let max_frame_latency = max_s2s_shout_frame_latency(&deliveries, &sent_at);
    let tail_latency = deliveries
        .iter()
        .map(|delivery| delivery.last_at)
        .max()
        .unwrap_or(send_end)
        .saturating_duration_since(send_end);
    let max_frame_gap = deliveries
        .iter()
        .map(|delivery| delivery.max_frame_gap)
        .max()
        .unwrap_or_default();
    let route_busy_cores = s2s_shout_route_busy_cores(route_resources.resolution_duration(), wall)
        .expect("cross-node shout duration should be non-zero");
    eprintln!(
        "s2s_shout_stream_metrics listeners={} frames={} routed_frames={} wall_ms={} first_latency_ms={} max_frame_latency_ms={} tail_latency_ms={} max_gap_ms={} route_resolution_ms={} route_total_ms={} route_busy_cores={:.2} budget_cores={:.2}",
        listeners.len(),
        frames.len(),
        route_resources.frames(),
        wall.as_millis(),
        max_first_frame_latency.as_millis(),
        max_frame_latency.as_millis(),
        tail_latency.as_millis(),
        max_frame_gap.as_millis(),
        route_resources.resolution_duration().as_millis(),
        route_resources.total_duration().as_millis(),
        route_busy_cores,
        S2S_SHOUT_ROUTE_CPU_BUDGET
    );

    assert!(
        max_frame_latency <= S2S_SHOUT_FRAME_LATENCY_BUDGET,
        "cross-node shout frame latency was {:?}, expected <= {:?}",
        max_frame_latency,
        S2S_SHOUT_FRAME_LATENCY_BUDGET
    );
    assert!(
        tail_latency <= S2S_SHOUT_FRAME_LATENCY_BUDGET,
        "cross-node shout tail latency was {:?}, expected <= {:?}",
        tail_latency,
        S2S_SHOUT_FRAME_LATENCY_BUDGET
    );
    assert!(
        max_frame_gap <= S2S_SHOUT_STREAM_GAP_BUDGET,
        "cross-node shout stream had a receive gap of {:?}, expected <= {:?}",
        max_frame_gap,
        S2S_SHOUT_STREAM_GAP_BUDGET
    );
    assert!(
        route_resources.frames() >= frames.len() as u64,
        "expected at least {} routed S2S target frames, saw {}",
        frames.len(),
        route_resources.frames()
    );
    assert!(
        route_busy_cores <= S2S_SHOUT_ROUTE_CPU_BUDGET,
        "S2S shout route resolution used {:.2} busy cores over {:?}, budget {:.2}",
        route_busy_cores,
        wall,
        S2S_SHOUT_ROUTE_CPU_BUDGET
    );
}

/// Verifies the deployed long-haul path from node 8 to node 1. The path has
/// roughly 208 ms RTT with bounded jitter, so a v2 distribution tree must
/// rebase its deadline at the receiving peer and deliver every ordered frame
/// without adding a server-side media timeline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2s_tree_voice_long_haul_node_8_to_node_1_is_immediate_without_expiry() {
    let _guard = s2s_network_test_guard().await;
    let (node_8, node_1) = spawn_s2s_long_haul_pair().await;
    wait_for_s2s_cluster(&[(&node_8, 8), (&node_1, 1)]).await;
    wait_for_s2s_voice_send_ready(&node_8, &[1]).await;

    node_8.authenticator.register_superuser(
        "long-haul-speaker",
        None,
        Some(80_001),
        vec!["admin".into()],
    );
    node_1
        .authenticator
        .register_user("long-haul-listener", None, Some(10_001), Vec::new());
    let listener = TestClient::connect_and_authenticate(&node_1, "long-haul-listener", None)
        .await
        .expect("node 1 long-haul listener");
    let speaker = TestClient::connect_and_authenticate(&node_8, "long-haul-speaker", None)
        .await
        .expect("node 8 long-haul speaker");
    wait_for_server_to_track_client(&node_8, listener.server_session).await;
    wait_for_server_to_track_client(&node_1, speaker.server_session).await;

    speaker
        .set_voice_target(s2s_voice_target(
            S2S_SHOUT_TARGET_SLOT,
            vec![s2s_voice_target_channel(0, true, false, None)],
        ))
        .await;
    wait_for_s2s_voice_target_installed(&node_8, &speaker, S2S_SHOUT_TARGET_SLOT).await;

    // Tree installation is ACK-gated. Prime the exact broadcast group until a
    // post-ACK original tree forward is observed, then discard the warmup
    // terminators before measuring the real talkspurt.
    listener.drain_now().await;
    wait_for_s2s_tree_voice_forwarding_between(&speaker, S2S_SHOUT_TARGET_SLOT, 8, 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    listener.drain_now().await;

    let tree_original_before =
        S2SDebugVoiceIoSnapshot::capture_between("application.voice.tree.original", 8, 1);
    let deadline_translation_before = s2s_prometheus_total(
        &node_1,
        "shitspeak_s2s_distribution_events_total",
        &[
            ("profile", "voice_realtime"),
            ("event", "deadline_translation"),
            ("result", "translated"),
        ],
    );
    let deadline_expiry_before = s2s_prometheus_total(
        &node_1,
        "shitspeak_s2s_distribution_events_total",
        &[("profile", "voice_realtime"), ("event", "deadline_expiry")],
    );

    let frames = (0..S2S_LONG_HAUL_FRAME_COUNT)
        .map(|offset| {
            let frame_number = 90_000 + offset as u64;
            (
                frame_number,
                Bytes::from(format!("s2s-long-haul-opus-frame-{frame_number}").into_bytes()),
            )
        })
        .collect::<Vec<_>>();
    let send_task = async {
        let sent_at = send_s2s_shout_voice_segment(&speaker, S2S_SHOUT_TARGET_SLOT, &frames).await;
        (Instant::now(), sent_at)
    };
    let receive_task = receive_s2s_shout_stream(&listener, &speaker, 0, &frames);
    let ((send_end, sent_at), delivery) = tokio::join!(send_task, receive_task);

    let tree_original_delta =
        S2SDebugVoiceIoSnapshot::capture_between("application.voice.tree.original", 8, 1)
            .saturating_sub(&tree_original_before)
            .sent_count;
    let deadline_translation_delta = s2s_prometheus_total(
        &node_1,
        "shitspeak_s2s_distribution_events_total",
        &[
            ("profile", "voice_realtime"),
            ("event", "deadline_translation"),
            ("result", "translated"),
        ],
    ) - deadline_translation_before;
    let deadline_expiry_delta = s2s_prometheus_total(
        &node_1,
        "shitspeak_s2s_distribution_events_total",
        &[("profile", "voice_realtime"), ("event", "deadline_expiry")],
    ) - deadline_expiry_before;
    let first_latency = delivery.first_at.saturating_duration_since(sent_at[0]);
    let max_latency = max_s2s_shout_frame_latency(std::slice::from_ref(&delivery), &sent_at);
    let tail_latency = delivery.last_at.saturating_duration_since(send_end);
    eprintln!(
        "s2s_long_haul_tree_voice_metrics source=8 destination=1 rtt_ms={} jitter_ms={} frames={} tree_original_frames={} deadline_translations={:.0} deadline_expiries={:.0} first_latency_ms={} max_latency_ms={} tail_latency_ms={} max_gap_ms={}",
        S2S_LONG_HAUL_ONE_WAY_LATENCY.as_millis() * 2,
        S2S_LONG_HAUL_JITTER.as_millis(),
        frames.len(),
        tree_original_delta,
        deadline_translation_delta,
        deadline_expiry_delta,
        first_latency.as_millis(),
        max_latency.as_millis(),
        tail_latency.as_millis(),
        delivery.max_frame_gap.as_millis(),
    );

    assert!(
        tree_original_delta >= frames.len() as u64,
        "node 8 did not send every measured long-haul frame through the active tree"
    );
    // Voice v3 uses an adjacent-hop local expiry. Unlike v2, it deliberately
    // has no wall-clock deadline translation at the receiver.
    assert_eq!(
        deadline_expiry_delta, 0.0,
        "node 1 expired a tree voice frame on the 208 ms RTT path"
    );
    assert!(
        max_latency <= S2S_LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET,
        "long-haul tree voice was held for {:?}, expected <= {:?}",
        max_latency,
        S2S_LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET
    );
    assert!(
        tail_latency <= S2S_LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET,
        "long-haul tree voice tail was held for {:?}, expected <= {:?}",
        tail_latency,
        S2S_LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET
    );
    assert!(
        delivery.max_frame_gap <= S2S_SHOUT_STREAM_GAP_BUDGET,
        "long-haul immediate delivery had a gap of {:?}, expected <= {:?}",
        delivery.max_frame_gap,
        S2S_SHOUT_STREAM_GAP_BUDGET
    );
}

/// Checks broadcast-style shout resilience when a different peer is hostile.
/// Expected: Alice shouts to root with `children=true`, forcing the S2S voice
/// service to broadcast to every alive peer. Server B's 500 healthy listeners
/// receive at least 99% of the ordered, byte-identical 10-second stream even
/// while server C drops and delays A's overlay data. S2S voice remains
/// best-effort, so bounded loss on the healthy path is acceptable here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2s_broadcast_shout_to_all_clients_survives_bad_node() {
    let _guard = s2s_network_test_guard().await;
    let bad_node_chaos = LinkChaos::new();
    let a_opts = TestServerOpts {
        max_users: (S2S_SHOUT_REMOTE_CLIENTS + 16) as u64,
        client_idle_timeout_secs: S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS / 1_000,
        authenticate_timeout_ms: S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS,
        auth_finalization_concurrency: S2S_SHOUT_AUTH_FINALIZATION_CONCURRENCY,
        ..TestServerOpts::default()
    };
    let b_opts = TestServerOpts {
        max_users: (S2S_SHOUT_REMOTE_CLIENTS + 16) as u64,
        client_idle_timeout_secs: S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS / 1_000,
        authenticate_timeout_ms: S2S_SHOUT_AUTHENTICATE_TIMEOUT_MS,
        auth_finalization_concurrency: S2S_SHOUT_AUTH_FINALIZATION_CONCURRENCY,
        ..TestServerOpts::default()
    };
    let c_opts = TestServerOpts {
        max_users: 16,
        s2s_inbound_chaos: Some(bad_node_chaos.clone()),
        ..TestServerOpts::default()
    };
    let (a, b, _c) = spawn_s2s_three_node_with_opts(a_opts, b_opts, c_opts).await;
    wait_for_s2s_cluster(&[(&a, 1), (&b, 2), (&_c, 3)]).await;

    a.authenticator
        .register_superuser("speaker", None, Some(1), vec!["admin".into()]);
    for idx in 0..S2S_SHOUT_REMOTE_CLIENTS {
        b.authenticator.register_user(
            &format!("remote-listener-{idx:03}"),
            None,
            Some(20_000 + idx as u32),
            Vec::new(),
        );
    }

    let listeners = connect_s2s_shout_listeners(&b, S2S_SHOUT_REMOTE_CLIENTS).await;
    let listener_sessions = listeners
        .iter()
        .map(|client| client.session_id)
        .collect::<Vec<_>>();
    assert!(
        wait_for_server_sessions_in_channel(&b, &listener_sessions, 0, S2S_DEADLINE)
            .await
            .is_some(),
        "server B should keep every broadcast listener in root"
    );

    let alice = TestClient::connect_and_authenticate_with_deadline(
        &a,
        "speaker",
        None,
        S2S_SHOUT_CONNECT_DEADLINE,
    )
    .await
    .expect("speaker");
    wait_for_server_to_track_client(&b, alice.server_session).await;
    alice
        .set_voice_target(s2s_voice_target(
            S2S_SHOUT_TARGET_SLOT,
            vec![s2s_voice_target_channel(0, true, false, None)],
        ))
        .await;
    wait_for_s2s_voice_target_installed(&a, &alice, S2S_SHOUT_TARGET_SLOT).await;
    alice.drain_now().await;
    for listener in &listeners {
        listener.drain_now().await;
    }
    wait_for_s2s_voice_send_ready(&a, &[2]).await;

    bad_node_chaos.add_latency(1, Duration::from_secs(5));
    bad_node_chaos.set_bandwidth(Some(1));
    bad_node_chaos.drop_next_of_type_from(1, MessageType::Data, S2S_SHOUT_FRAMES as u32);

    let frames = s2s_shout_voice_segment(60_000);
    assert!(
        s2s_shout_segment_send_span(&frames) >= S2S_SHOUT_MIN_SPEAK_SPAN,
        "broadcast shout test should continuously speak for at least {:?}",
        S2S_SHOUT_MIN_SPEAK_SPAN
    );

    let speak_start = Instant::now();
    let route_sample = S2SRouteResourceSample::capture_target();
    let send_task = async {
        let sent_at = send_s2s_shout_voice_segment(&alice, S2S_SHOUT_TARGET_SLOT, &frames).await;
        (Instant::now(), sent_at)
    };
    let receive_task = async {
        join_all(listeners.iter().enumerate().map(|(idx, listener)| {
            receive_s2s_shout_stream_with_loss_budget(listener, &alice, idx, &frames)
        }))
        .await
    };
    let ((send_end, sent_at), deliveries) = tokio::join!(send_task, receive_task);
    let route_resources = route_sample.finish();
    let wall = speak_start.elapsed();

    let max_first_frame_latency = deliveries
        .iter()
        .map(|delivery| delivery.first_at.saturating_duration_since(sent_at[0]))
        .max()
        .unwrap_or_default();
    let max_frame_latency = max_s2s_shout_frame_latency(&deliveries, &sent_at);
    let tail_latency = deliveries
        .iter()
        .map(|delivery| delivery.last_at)
        .max()
        .unwrap_or(send_end)
        .saturating_duration_since(send_end);
    let max_frame_gap = deliveries
        .iter()
        .map(|delivery| delivery.max_frame_gap)
        .max()
        .unwrap_or_default();
    let route_busy_cores = s2s_shout_route_busy_cores(route_resources.resolution_duration(), wall)
        .expect("broadcast shout duration should be non-zero");
    eprintln!(
        "s2s_broadcast_shout_bad_node_metrics listeners={} frames={} routed_frames={} wall_ms={} first_latency_ms={} max_frame_latency_ms={} tail_latency_ms={} max_gap_ms={} route_resolution_ms={} route_total_ms={} route_busy_cores={:.2} budget_cores={:.2}",
        listeners.len(),
        frames.len(),
        route_resources.frames(),
        wall.as_millis(),
        max_first_frame_latency.as_millis(),
        max_frame_latency.as_millis(),
        tail_latency.as_millis(),
        max_frame_gap.as_millis(),
        route_resources.resolution_duration().as_millis(),
        route_resources.total_duration().as_millis(),
        route_busy_cores,
        S2S_SHOUT_ROUTE_CPU_BUDGET
    );

    assert!(
        max_frame_latency <= S2S_SHOUT_FRAME_LATENCY_BUDGET,
        "broadcast shout frame latency was {:?}, expected <= {:?}",
        max_frame_latency,
        S2S_SHOUT_FRAME_LATENCY_BUDGET
    );
    assert!(
        tail_latency <= S2S_SHOUT_FRAME_LATENCY_BUDGET,
        "broadcast shout tail latency was {:?}, expected <= {:?}",
        tail_latency,
        S2S_SHOUT_FRAME_LATENCY_BUDGET
    );
    assert!(
        max_frame_gap <= S2S_SHOUT_BAD_NODE_STREAM_GAP_BUDGET,
        "broadcast shout stream had a receive gap of {:?}, expected <= {:?}",
        max_frame_gap,
        S2S_SHOUT_BAD_NODE_STREAM_GAP_BUDGET
    );
    assert!(
        route_resources.frames() >= frames.len() as u64,
        "expected at least {} routed S2S target frames on the healthy node, saw {}",
        frames.len(),
        route_resources.frames()
    );
    assert!(
        route_busy_cores <= S2S_SHOUT_ROUTE_CPU_BUDGET,
        "broadcast shout route resolution used {:.2} busy cores over {:?}, budget {:.2}",
        route_busy_cores,
        wall,
        S2S_SHOUT_ROUTE_CPU_BUDGET
    );
}

/// Measures cross-node traffic amplification for a root shout that includes
/// subchannels.
/// Expected: the current broadcast path sends at most one voice overlay packet
/// per frame and first hop. Multiple final destinations sharing a first hop are
/// carried in one multicast envelope. Repair may add at most one proactive copy
/// per destination, so the test bounds total traffic at twice the broadcast
/// ceiling and prints the excess over the multicast minimum.
#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2s_root_children_shout_reports_cross_node_traffic_amplification() {
    let _guard = s2s_network_test_guard().await;
    run_s2s_root_children_shout_traffic(false).await;
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2s_root_children_shout_uses_tree_delivery_budget() {
    let _guard = s2s_network_test_guard().await;
    run_s2s_root_children_shout_traffic(true).await;
}

#[cfg(debug_assertions)]
async fn run_s2s_root_children_shout_traffic(tree_delivery_enabled: bool) {
    // This scenario measures traffic amplification across a six-node tree.
    // Its receive assertions are not a low-latency playout contract, so give
    // reactive repair enough room to absorb host scheduler contention during a
    // full runtime run without relaxing the delivered-frame budget. The
    // enlarged test-only reorder buffer holds the 20 ms stream while a valid
    // repair completes instead of dropping its suffix, while leaving room
    // before the receive timeout for a deadline flush.
    let cluster = spawn_s2s_convergence_cluster_with_voice_options(
        tree_delivery_enabled,
        None,
        Some(1_000),
        Some(512),
    )
    .await;
    cluster.connect_full_mesh().await;
    wait_for_convergence_cluster(&cluster).await;
    let servers = cluster.servers.iter().collect::<Vec<_>>();

    let speaker_server = servers[0];
    let first_listener_server = servers[1];
    let second_listener_server = servers[2];
    speaker_server
        .authenticator
        .register_superuser("speaker", None, Some(1), vec!["admin".into()]);
    first_listener_server.authenticator.register_user(
        "traffic-listener-a",
        None,
        Some(31_001),
        Vec::new(),
    );
    second_listener_server.authenticator.register_user(
        "traffic-listener-b",
        None,
        Some(31_002),
        Vec::new(),
    );

    let channel_ids = create_s2s_root_shout_traffic_tree(speaker_server).await;
    wait_for_s2s_channels_on_servers(&servers, &channel_ids, S2S_DEADLINE).await;
    first_listener_server
        .server
        .get_user_channel_cache()
        .remember_last_channel("31001", 11)
        .await
        .expect("remember first listener channel");
    second_listener_server
        .server
        .get_user_channel_cache()
        .remember_last_channel("31002", 21)
        .await
        .expect("remember second listener channel");

    let first_listener = connect_s2s_shout_listener(first_listener_server, "traffic-listener-a")
        .await
        .expect("first traffic listener");
    let second_listener = connect_s2s_shout_listener(second_listener_server, "traffic-listener-b")
        .await
        .expect("second traffic listener");
    assert!(
        wait_for_server_sessions_in_channel(
            first_listener_server,
            &[first_listener.session_id],
            11,
            S2S_DEADLINE,
        )
        .await
        .is_some(),
        "first traffic listener should enter the target subtree"
    );
    assert!(
        wait_for_server_sessions_in_channel(
            second_listener_server,
            &[second_listener.session_id],
            21,
            S2S_DEADLINE,
        )
        .await
        .is_some(),
        "second traffic listener should enter the target subtree"
    );

    let alice = TestClient::connect_and_authenticate_with_deadline(
        speaker_server,
        "speaker",
        None,
        S2S_SHOUT_CONNECT_DEADLINE,
    )
    .await
    .expect("traffic speaker");
    wait_for_server_to_track_client(first_listener_server, alice.server_session).await;
    wait_for_server_to_track_client(second_listener_server, alice.server_session).await;
    alice
        .set_voice_target(s2s_voice_target(
            S2S_SHOUT_TARGET_SLOT,
            vec![s2s_voice_target_channel(0, true, false, None)],
        ))
        .await;
    wait_for_s2s_voice_target_installed(speaker_server, &alice, S2S_SHOUT_TARGET_SLOT).await;
    alice.drain_now().await;
    first_listener.drain_now().await;
    second_listener.drain_now().await;
    let node_ids: Vec<u16> = (1..=servers.len() as u16).collect();
    for (index, server) in servers.iter().copied().enumerate() {
        let node_id = index as u16 + 1;
        let peers: Vec<_> = node_ids
            .iter()
            .copied()
            .filter(|peer| *peer != node_id)
            .collect();
        wait_for_s2s_direct_voice_send_ready(server, &peers).await;
    }

    if tree_delivery_enabled {
        // Tree installation is ACK-gated. Prime the exact broadcast group
        // before proving end-to-end delivery below.
        wait_for_s2s_tree_voice_forwarding(speaker_server, &alice, S2S_SHOUT_TARGET_SLOT).await;
        alice.drain_now().await;
        first_listener.drain_now().await;
        second_listener.drain_now().await;
    }
    // Transport send-readiness does not prove that the complete application
    // path and receiver reorder state are warm. Require the same end-to-end
    // marker fence for legacy and tree delivery before measuring traffic.
    wait_for_s2s_root_shout_delivery(
        &alice,
        &[&first_listener, &second_listener],
        S2S_SHOUT_TARGET_SLOT,
    )
    .await;

    let frames = s2s_shout_voice_segment(52_000);
    assert!(
        s2s_shout_segment_send_span(&frames) >= S2S_SHOUT_MIN_SPEAK_SPAN,
        "traffic amplification measurement should continuously speak for at least {:?}",
        S2S_SHOUT_MIN_SPEAK_SPAN
    );

    let legacy_before = S2SDebugVoiceIoSnapshot::capture("application.voice.frame");
    let tree_original_before = S2SDebugVoiceIoSnapshot::capture("application.voice.tree.original");
    let tree_repair_before = S2SDebugVoiceIoSnapshot::capture("application.voice.tree.repair");
    let speak_start = Instant::now();
    let send_task =
        async { send_s2s_shout_voice_segment(&alice, S2S_SHOUT_TARGET_SLOT, &frames).await };
    let receive_task = async {
        join_all(
            [&first_listener, &second_listener]
                .into_iter()
                .enumerate()
                .map(|(idx, listener)| {
                    receive_s2s_shout_stream_with_loss_budget(listener, &alice, idx, &frames)
                }),
        )
        .await
    };
    let (_sent_at, _deliveries) = tokio::join!(send_task, receive_task);
    let legacy_delta =
        S2SDebugVoiceIoSnapshot::capture("application.voice.frame").saturating_sub(&legacy_before);
    let tree_original_delta = S2SDebugVoiceIoSnapshot::capture("application.voice.tree.original")
        .saturating_sub(&tree_original_before);
    let tree_repair_delta = S2SDebugVoiceIoSnapshot::capture("application.voice.tree.repair")
        .saturating_sub(&tree_repair_before);
    let voice_delta = legacy_delta
        .clone()
        .saturating_add(&tree_original_delta)
        .saturating_add(&tree_repair_delta);

    let frame_count = frames.len() as u64;
    let remote_nodes = (servers.len() - 1) as u64;
    let minimum_first_hops = 1u64;
    let broadcast_packet_budget = frame_count * remote_nodes;
    let repair_packet_budget = broadcast_packet_budget * 2;
    let minimum_packet_budget = frame_count * minimum_first_hops;
    let duplicate_packets = voice_delta.sent_count.saturating_sub(minimum_packet_budget);
    let amplification = if minimum_packet_budget == 0 {
        0.0
    } else {
        voice_delta.sent_count as f64 / minimum_packet_budget as f64
    };
    let average_packet_bytes = if voice_delta.sent_count == 0 {
        0.0
    } else {
        voice_delta.sent_bytes as f64 / voice_delta.sent_count as f64
    };
    let estimated_minimum_bytes = average_packet_bytes * minimum_packet_budget as f64;
    let estimated_duplicate_bytes =
        (voice_delta.sent_bytes as f64 - estimated_minimum_bytes).max(0.0);
    eprintln!(
        "s2s_root_children_shout_traffic frames={} remote_nodes={} minimum_first_hops={} sent_packets={} minimum_packets={} duplicate_packets={} amplification={:.2}x sent_bytes={} estimated_minimum_bytes={:.0} estimated_duplicate_bytes={:.0} avg_packet_bytes={:.1} recv_packets={} recv_bytes={} legacy_packets={} tree_original_packets={} tree_repair_packets={}",
        frame_count,
        remote_nodes,
        minimum_first_hops,
        voice_delta.sent_count,
        minimum_packet_budget,
        duplicate_packets,
        amplification,
        voice_delta.sent_bytes,
        estimated_minimum_bytes,
        estimated_duplicate_bytes,
        average_packet_bytes,
        voice_delta.recv_count,
        voice_delta.recv_bytes,
        legacy_delta.sent_count,
        tree_original_delta.sent_count,
        tree_repair_delta.sent_count,
    );

    assert!(
        voice_delta.sent_count >= minimum_packet_budget,
        "root+children shout sent fewer than one multicast packet per frame"
    );
    if tree_delivery_enabled {
        // Tree replacement is ACK-gated. A frame may legitimately use the
        // compatibility multicast while a new candidate is installing, but
        // this scenario must still exercise the active tree path.
        assert!(
            tree_original_delta.sent_count > 0,
            "tree delivery never became active during the root-shout stream"
        );
    }
    // Tree edges are logical source-tree edges. The current underlay may
    // route one logical edge across an alternate physical hop, so physical IO
    // is bounded at two copies per remote node while exact tree use is proved
    // by the separately classified original-frame counter above.
    let packet_budget = repair_packet_budget;
    assert!(
        voice_delta.sent_count <= packet_budget,
        "root+children shout exceeded the {} delivery packet budget",
        if tree_delivery_enabled {
            "tree"
        } else {
            "legacy"
        }
    );
    assert!(
        voice_delta.recv_count <= packet_budget,
        "root+children shout exceeded the {} delivery receive budget",
        if tree_delivery_enabled {
            "tree"
        } else {
            "legacy"
        }
    );

    // Keep the shared network-test guard held until every server has stopped.
    // Dropping TestServer aborts its run task as a fallback, which can leave
    // S2S background work competing with the next heavyweight voice scenario.
    drop(servers);
    join_all(
        cluster
            .servers
            .into_iter()
            .map(TestServer::shutdown_gracefully),
    )
    .await;
}

/// Checks that channel creation is replicated to another S2S node.
/// Expected: Bob receives `ChannelState` for `S2S Lobby` and server B advances
/// its channel log. Channel semantics come from Mumble's
/// `D:\mumble\src\murmur\Messages.cpp::msgChannelState` and shitspeak's
/// `D:\shitspeak\message.go::handleChannelStateMessage`; this crate's S2S
/// replication supplies the cross-node log propagation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_channel_replication_propagates() {
    let _guard = s2s_network_test_guard().await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_temporary_channel_creation_moves_creator() {
    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let _bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    alice.create_channel(0, "S2S Temp", true).await;

    let created = alice
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.name.as_deref() == Some("S2S Temp")
                        && cs.temporary == Some(true)
                        && cs.channel_id.is_some())
            },
            S2S_DEADLINE,
        )
        .await
        .expect("Alice should receive the temporary channel creation");
    let temp_channel_id = match created {
        Message::ChannelState(cs) => cs.channel_id.expect("created channel id"),
        other => panic!("expected ChannelState, got {other:?}"),
    };

    let moved = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id)
                        && us.channel_id == Some(temp_channel_id))
            },
            CLIENT_DEADLINE,
        )
        .await;
    assert!(
        moved.is_some(),
        "temporary channel creator should be moved immediately in S2S mode"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_empty_temporary_channel_delete_replicates_to_peer_node() {
    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    alice.create_channel(0, "S2S Temp Delete", true).await;

    let created = bob
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.name.as_deref() == Some("S2S Temp Delete")
                        && cs.temporary == Some(true)
                        && cs.channel_id.is_some())
            },
            S2S_DEADLINE,
        )
        .await
        .expect("Bob should receive the replicated temporary channel creation");
    let temp_channel_id = match created {
        Message::ChannelState(cs) => cs.channel_id.expect("created channel id"),
        other => panic!("expected ChannelState, got {other:?}"),
    };

    let moved = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id)
                        && us.channel_id == Some(temp_channel_id))
            },
            CLIENT_DEADLINE,
        )
        .await;
    assert!(
        moved.is_some(),
        "precondition: Alice should be inside the temporary channel"
    );

    alice.move_to_channel(0).await;

    let removed = bob
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == temp_channel_id),
            S2S_DEADLINE,
        )
        .await;
    assert!(
        removed.is_some(),
        "temporary channel deletion should replicate to peer-node clients"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_temporary_channel_survives_when_remote_creator_remains_inside() {
    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    alice.create_channel(0, "S2S Temp Occupied", true).await;

    let created = bob
        .recv_until(
            |m| {
                matches!(m, Message::ChannelState(cs)
                    if cs.name.as_deref() == Some("S2S Temp Occupied")
                        && cs.temporary == Some(true)
                        && cs.channel_id.is_some())
            },
            S2S_DEADLINE,
        )
        .await
        .expect("Bob should receive the replicated temporary channel creation");
    let temp_channel_id = match created {
        Message::ChannelState(cs) => cs.channel_id.expect("created channel id"),
        other => panic!("expected ChannelState, got {other:?}"),
    };

    let alice_moved = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id)
                        && us.channel_id == Some(temp_channel_id))
            },
            CLIENT_DEADLINE,
        )
        .await;
    assert!(
        alice_moved.is_some(),
        "precondition: Alice should be inside the temporary channel"
    );

    bob.move_to_channel(temp_channel_id).await;

    let bob_joined_locally = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(b.server.get_clients().get_client(bob.server_session))
                .is_some_and(|client| client.get_current_channel_id() == temp_channel_id)
        })
    })
    .await;
    assert!(
        bob_joined_locally,
        "Bob should join the temp channel on node B"
    );

    let alice_replicated_to_b = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(b.server.get_clients().get_client(alice.server_session))
                .is_some_and(|client| client.get_current_channel_id() == temp_channel_id)
        })
    })
    .await;
    assert!(
        alice_replicated_to_b,
        "node B should know Alice still occupies the temp channel before Bob leaves"
    );

    alice.drain_now().await;
    bob.drain_now().await;

    bob.move_to_channel(0).await;

    let bob_left = wait_until(CLIENT_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(b.server.get_clients().get_client(bob.server_session))
                .is_some_and(|client| client.get_current_channel_id() == 0)
        })
    })
    .await;
    assert!(bob_left, "Bob should leave the temp channel");

    let removed = alice
        .recv_until(
            |m| matches!(m, Message::ChannelRemove(cr) if cr.channel_id == temp_channel_id),
            Duration::from_secs(2),
        )
        .await;
    assert!(
        removed.is_none(),
        "temporary channel must not be removed while Alice still occupies it on node A"
    );

    assert!(
        a.server
            .get_channels()
            .get_channel(temp_channel_id)
            .await
            .is_some(),
        "node A should retain the occupied temporary channel"
    );
    assert!(
        b.server
            .get_channels()
            .get_channel(temp_channel_id)
            .await
            .is_some(),
        "node B should retain the occupied temporary channel"
    );
}

/// Checks that a node joining with a divergent channel history reconciles the
/// channel tree before remote client state can expose channels from the losing
/// history. Expected: the higher-version channel history wins, both connected
/// clients receive the repaired layout, and Alice never sees Bob in B's
/// discarded channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_divergent_channel_layout_converges_before_client_integration() {
    let _guard = s2s_network_test_guard().await;
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
            seed_addresses: Vec::new(),
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
            seed_addresses: Vec::new(),
        },
    )
    .await;
    wait_for_s2s_runtime(&a).await;
    wait_for_s2s_runtime(&b).await;

    a.server
        .get_channels()
        .create_channel(shitspeak_state::Channel::new(
            42,
            "Elected Lobby".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .expect("create A channel 42");
    a.server
        .get_channels()
        .create_channel(shitspeak_state::Channel::new(
            43,
            "Elected Annex".to_owned(),
            1,
            0,
            Some(0),
        ))
        .await
        .expect("create A channel 43");
    b.server
        .get_channels()
        .create_channel(shitspeak_state::Channel::new(
            84,
            "Discarded Lobby".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .expect("create B-only channel 84");

    register_pair_users(&a, &b);
    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");
    alice.move_to_channel(42).await;
    bob.move_to_channel(84).await;

    let local_moves_applied = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            let alice_channel = handle
                .block_on(a.server.get_clients().get_client(alice.server_session))
                .map(|client| client.get_current_channel_id());
            let bob_channel = handle
                .block_on(b.server.get_clients().get_client(bob.server_session))
                .map(|client| client.get_current_channel_id());
            alice_channel == Some(42) && bob_channel == Some(84)
        })
    })
    .await;
    assert!(
        local_moves_applied,
        "local clients should start in their pre-merge layouts"
    );

    alice.drain_now().await;
    bob.drain_now().await;

    add_s2s_peer_address(&a, 2, b_s2s_port).await;
    add_s2s_peer_address(&b, 1, a_s2s_port).await;
    wait_for_s2s_pair(&a, &b).await;

    let channel_layout_converged = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            a.server.get_channels().current_version() == 2
                && b.server.get_channels().current_version() == 2
                && handle
                    .block_on(a.server.get_channels().get_channel(42))
                    .is_some()
                && handle
                    .block_on(a.server.get_channels().get_channel(43))
                    .is_some()
                && handle
                    .block_on(a.server.get_channels().get_channel(84))
                    .is_none()
                && handle
                    .block_on(b.server.get_channels().get_channel(42))
                    .is_some()
                && handle
                    .block_on(b.server.get_channels().get_channel(43))
                    .is_some()
                && handle
                    .block_on(b.server.get_channels().get_channel(84))
                    .is_none()
        })
    })
    .await;
    assert!(
        channel_layout_converged,
        "servers should converge on A's channel layout before client integration"
    );

    let bob_received_repaired_layout = tokio::time::timeout(S2S_DEADLINE, async {
        let mut saw_42 = bob.initial_channel_states.iter().any(|channel| {
            channel.channel_id == Some(42) && channel.name.as_deref() == Some("Elected Lobby")
        });
        let mut saw_43 = bob.initial_channel_states.iter().any(|channel| {
            channel.channel_id == Some(43) && channel.name.as_deref() == Some("Elected Annex")
        });
        let mut saw_remove_84 = false;

        while !(saw_42 && saw_43 && saw_remove_84) {
            let Some(message) = bob.recv(CLIENT_DEADLINE).await else {
                return false;
            };
            match message {
                Message::ChannelState(channel) => {
                    if channel.channel_id == Some(42)
                        && channel.name.as_deref() == Some("Elected Lobby")
                    {
                        saw_42 = true;
                    }
                    if channel.channel_id == Some(43)
                        && channel.name.as_deref() == Some("Elected Annex")
                    {
                        saw_43 = true;
                    }
                }
                Message::ChannelRemove(remove) if remove.channel_id == 84 => {
                    saw_remove_84 = true;
                }
                _ => {}
            }
        }
        true
    })
    .await
    .unwrap_or(false);
    assert!(
        bob_received_repaired_layout,
        "Bob should receive the elected channels and removal of his discarded local channel"
    );

    let final_client_state_safe = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            let bob_on_a = handle.block_on(a.server.get_clients().get_client(bob.server_session));
            let bob_on_b = handle.block_on(b.server.get_clients().get_client(bob.server_session));
            bob_on_a
                .as_ref()
                .is_some_and(|client| client.get_current_channel_id() != 84)
                && bob_on_b
                    .as_ref()
                    .is_some_and(|client| client.get_current_channel_id() != 84)
        })
    })
    .await;
    assert!(
        final_client_state_safe,
        "Bob should be materialized only in channels from the elected layout; A client versions={:?}, B client versions={:?}",
        a.server.get_clients().snapshot_with_versions().await.1,
        b.server.get_clients().snapshot_with_versions().await.1,
    );

    let mut alice_buffered = alice.drain_now().await;
    assert!(
        !alice_buffered.iter().any(|message| {
            matches!(message, Message::UserState(state)
                if state.session == Some(bob.session_id) && state.channel_id == Some(84))
        }),
        "Alice must not receive Bob in the discarded B-only channel"
    );

    let alice_saw_bob_safely = if alice_buffered.iter().any(|message| {
        matches!(message, Message::UserState(state)
            if state.session == Some(bob.session_id)
                && user_state_name_matches(state.name.as_deref(), "bob")
                && state.channel_id != Some(84))
    }) {
        true
    } else {
        tokio::time::timeout(S2S_DEADLINE, async {
            loop {
                let Some(message) = alice.recv(S2S_DEADLINE).await else {
                    return false;
                };
                match message {
                    Message::UserState(state)
                        if state.session == Some(bob.session_id)
                            && state.channel_id == Some(84) =>
                    {
                        return false;
                    }
                    Message::UserState(state)
                        if state.session == Some(bob.session_id)
                            && user_state_name_matches(state.name.as_deref(), "bob") =>
                    {
                        return true;
                    }
                    other => alice_buffered.push(other),
                }
            }
        })
        .await
        .unwrap_or(false)
    };
    assert!(
        alice_saw_bob_safely,
        "Alice should eventually see Bob only after his state is safe for the elected layout"
    );

    let late_bob_view = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("late bob observer");
    assert!(
        late_bob_view.initial_channel_states.iter().any(|channel| {
            channel.channel_id == Some(42) && channel.name.as_deref() == Some("Elected Lobby")
        }),
        "new clients on B should receive channel 42 from the elected layout"
    );
    assert!(
        late_bob_view.initial_channel_states.iter().any(|channel| {
            channel.channel_id == Some(43) && channel.name.as_deref() == Some("Elected Annex")
        }),
        "new clients on B should receive channel 43 from the elected layout"
    );
    assert!(
        late_bob_view
            .initial_channel_states
            .iter()
            .all(|channel| channel.channel_id != Some(84)),
        "new clients on B should not receive the discarded channel"
    );
}

/// Checks client add, update, and remove replication across S2S nodes.
/// Expected: Bob sees Alice join, self-mute, and leave, and server B's remote
/// client index materializes then removes Alice. The user-state/remove
/// behavior comes from Mumble's `D:\mumble\src\murmur\Messages.cpp` and
/// shitspeak's `D:\shitspeak\message.go`; this crate's S2S client repository
/// replication extends it across servers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_client_replication_propagates_add_update_remove() {
    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    wait_for_server_to_track_client(&b, alice.server_session).await;
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

    let saw_add = client_sees_user_state(&bob, alice_session, "alice").await;
    assert!(saw_add, "Bob should see Alice's replicated add");

    let bob_session = bob.server_session;
    let bob_indexed_on_a = wait_until(S2S_DEADLINE, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(a.server.get_clients().get_client(bob_session))
                .is_some()
        })
    })
    .await;
    assert!(
        bob_indexed_on_a,
        "Server A should materialize Bob in its remote index"
    );

    let saw_reverse_add = client_sees_user_state(&alice, bob_session, "bob").await;
    assert!(saw_reverse_add, "Alice should see Bob's replicated add");

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

/// Diagnostic reproduction for channel-move lag under a large S2S cluster.
///
/// Scenario:
/// - 8 S2S nodes, full mesh.
/// - 150 synthetic clients published on node 1.
/// - 400ms added inbound latency on every S2S link.
/// - Optional pathological links from node 1 to nodes 7/8 at >15s.
///
/// Run with:
/// `cargo test s2s_eight_node_400ms_150_clients_channel_move_lag_diagnostic -- --ignored --nocapture`
#[ignore = "on-demand S2S move-lag diagnostic; run explicitly with --ignored"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn s2s_eight_node_400ms_150_clients_channel_move_lag_diagnostic() {
    let _guard = s2s_network_test_guard().await;
    let cluster = spawn_s2s_lag_diagnostic_cluster().await;
    println!(
        "lag-diagnostic setup: spawned {} S2S runtimes",
        cluster.servers.len()
    );
    cluster.servers[0]
        .authenticator
        .register_user("observer", None, Some(990_001), vec![]);

    cluster.connect_full_mesh().await;
    wait_for_convergence_cluster(&cluster).await;
    println!("lag-diagnostic setup: full mesh converged without injected latency");

    let diagnostic_channel = shitspeak_state::Channel::new(
        S2S_LAG_DIAGNOSTIC_CHANNEL_ID,
        "Lag Diagnostic",
        0,
        0,
        Some(0),
    );
    let diagnostic_channel_op = shitspeak_state::ChannelOp::CreateChannel {
        channel: diagnostic_channel,
    };
    assert!(
        cluster.servers[0]
            .server
            .s2s_manager()
            .propose_channel_op(None, diagnostic_channel_op)
            .await
            .is_proposed(),
        "diagnostic channel should be created through strict S2S replication"
    );
    let channel_ready = wait_until(Duration::from_secs(30), || {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            cluster.servers.iter().all(|server| {
                handle
                    .block_on(
                        server
                            .server
                            .get_channels()
                            .get_channel(S2S_LAG_DIAGNOSTIC_CHANNEL_ID),
                    )
                    .is_some()
            })
        })
    })
    .await;
    assert!(
        channel_ready,
        "all nodes should know diagnostic channel before client moves"
    );
    println!("lag-diagnostic setup: diagnostic channel replicated");

    let sessions = add_synthetic_published_user_count(
        &cluster.servers[0],
        1,
        S2S_LAG_DIAGNOSTIC_CLIENTS_ON_NODE,
    )
    .await;
    let sessions_by_node = vec![sessions.clone()];
    assert!(
        wait_for_servers_to_track_users(
            &cluster.servers,
            &sessions_by_node,
            Duration::from_secs(45),
        )
        .await,
        "all nodes should track node 1 synthetic clients before measured move"
    );
    println!(
        "lag-diagnostic setup: all nodes materialized {} node-1 synthetic users",
        sessions.len()
    );
    let observer = TestClient::connect_and_authenticate(&cluster.servers[0], "observer", None)
        .await
        .expect("observer");
    assert!(
        wait_for_observer_to_know_users(&observer, &sessions, Duration::from_secs(10)).await,
        "node 1 observer should receive initial synthetic user states before measured move"
    );
    observer.drain_now().await;
    println!("lag-diagnostic setup: node 1 observer is caught up");

    apply_uniform_s2s_latency(
        &cluster,
        Duration::from_millis(S2S_LAG_DIAGNOSTIC_BASE_LATENCY_MS),
    );
    apply_slow_s2s_links_from_node(
        &cluster,
        1,
        &[7, 8],
        Duration::from_millis(S2S_LAG_DIAGNOSTIC_SLOW_LINK_LATENCY_MS),
    );
    println!(
        "lag-diagnostic setup: applied {}ms latency to all links and {}ms node1->{{7,8}} slow links; hello_dead={}ms",
        S2S_LAG_DIAGNOSTIC_BASE_LATENCY_MS,
        S2S_LAG_DIAGNOSTIC_SLOW_LINK_LATENCY_MS,
        S2S_LAG_DIAGNOSTIC_HELLO_DEAD_MS
    );

    let local_move_elapsed = move_synthetic_clients_to_channel(
        &cluster.servers[0],
        &sessions,
        S2S_LAG_DIAGNOSTIC_CHANNEL_ID,
    )
    .await;
    println!(
        "lag-diagnostic move: node 1 committed {} local channel moves in {:?}",
        sessions.len(),
        local_move_elapsed
    );

    let local_visible = wait_for_server_sessions_in_channel(
        &cluster.servers[0],
        &sessions,
        S2S_LAG_DIAGNOSTIC_CHANNEL_ID,
        Duration::from_secs(1),
    )
    .await;
    assert!(
        local_visible.is_some(),
        "node 1 should apply synthetic moves locally immediately"
    );
    let local_observer_elapsed = wait_for_observer_sessions_in_channel(
        &observer,
        &sessions,
        S2S_LAG_DIAGNOSTIC_CHANNEL_ID,
        Duration::from_secs(5),
    )
    .await
    .unwrap_or_else(|| {
        panic!(
            "node 1 observer did not receive all {} local channel moves within 5s",
            sessions.len()
        )
    });
    println!(
        "lag-diagnostic local-observer: node 1 observer received all {} channel moves after {:?}",
        sessions.len(),
        local_observer_elapsed
    );

    let mut slowest = Duration::ZERO;
    for (idx, server) in cluster.servers.iter().enumerate().skip(1) {
        let node_id = idx + 1;
        let elapsed = wait_for_server_sessions_in_channel(
            server,
            &sessions,
            S2S_LAG_DIAGNOSTIC_CHANNEL_ID,
            Duration::from_secs(S2S_LAG_DIAGNOSTIC_REMOTE_WAIT_SECS),
        )
        .await;
        match elapsed {
            Some(elapsed) => {
                slowest = slowest.max(elapsed);
                println!(
                    "lag-diagnostic remote: node {node_id} saw all {} moves after {:?}",
                    sessions.len(),
                    elapsed
                );
            }
            None => {
                let (known, moved, not_moved, node1_version, versions) =
                    server_session_channel_summary(
                        server,
                        &sessions,
                        S2S_LAG_DIAGNOSTIC_CHANNEL_ID,
                    )
                    .await;
                panic!(
                    "node {node_id} did not materialize all {} channel moves within {}s; known={known}, moved={moved}, not_moved={not_moved:?}, node1_version={node1_version:?}, versions={versions:?}",
                    sessions.len(),
                    S2S_LAG_DIAGNOSTIC_REMOTE_WAIT_SECS,
                );
            }
        }
    }

    println!(
        "lag-diagnostic summary: slowest remote materialization {:?}; slow links above 15s are expected to dominate if client replication proposals or next-hop sends are serialized",
        slowest
    );
}

/// Checks client-visible stability in a 6-node cluster after one redundant
/// direct transport edge is severed. Expected: because node 6 is still reachable
/// through other links, clients on node 1 do not receive unsolicited
/// `UserState` or `UserRemove` for node 6 users.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn s2s_six_node_800_users_direct_link_severed_no_client_visible_churn() {
    let _guard = s2s_network_test_guard().await;
    let cluster = spawn_s2s_convergence_cluster().await;
    let servers = &cluster.servers;
    println!("direct-link-sever setup: spawned 6 S2S runtimes");

    for (idx, server) in servers.iter().enumerate() {
        server
            .authenticator
            .register_user("observer", None, Some(900_000 + idx as u32), vec![]);
    }
    let mut sessions_by_node = Vec::with_capacity(servers.len());
    for (idx, server) in servers.iter().enumerate() {
        sessions_by_node.push(add_synthetic_published_users(server, (idx + 1) as u16).await);
        println!(
            "direct-link-sever setup: node {} published {} synthetic users",
            idx + 1,
            sessions_by_node[idx].len()
        );
    }
    cluster.connect_full_mesh().await;
    println!("direct-link-sever setup: full mesh addresses installed");
    wait_for_convergence_cluster(&cluster).await;
    println!("direct-link-sever setup: overlay converged");
    assert!(
        wait_for_servers_to_track_users(&servers, &sessions_by_node, Duration::from_secs(45)).await,
        "all servers should materialize all synthetic users before the measured cut"
    );
    let observer = TestClient::connect_and_authenticate(&servers[0], "observer", None)
        .await
        .expect("observer");
    println!("direct-link-sever setup: observer connected");
    assert!(
        wait_for_observer_to_know_users(&observer, &sessions_by_node[5], Duration::from_secs(45))
            .await,
        "observer should receive node 6's initial UserState set before the measured cut"
    );
    observer.drain_now().await;

    let node1_transport = servers[0]
        .server
        .s2s_manager()
        .transport()
        .expect("node 1 transport");
    let node6_transport = servers[5]
        .server
        .s2s_manager()
        .transport()
        .expect("node 6 transport");
    node1_transport.forget_node(6).await;
    node6_transport.forget_node(1).await;

    assert!(
        !observer_sees_user_churn(&observer, &sessions_by_node[5], Duration::from_secs(6)).await,
        "severing only the direct node 1 <-> node 6 link should not emit UserState/UserRemove for node 6 users while alternate routes remain"
    );
    assert!(
        wait_until(Duration::from_secs(6), || {
            servers[0]
                .server
                .s2s_manager()
                .overlay()
                .is_some_and(|overlay| {
                    overlay.alive_members().contains(&6)
                        && overlay.route_to(6, ServiceLevel::Reliable).is_some()
                })
        })
        .await,
        "node 1 should still consider node 6 alive and routed through alternate links"
    );

    println!(
        "direct-link-sever stability: no UserState/UserRemove for {} node 6 users over 6s; node 6 stayed reachable",
        sessions_by_node[5].len()
    )
}

/// Measures client-visible convergence in a 6-node cluster with 800 published
/// users per node after one node goes unreachable without a graceful S2S leave.
/// Expected: a client on a surviving node receives `UserRemove` for every
/// published user from the failed node after failure detection ages it out.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn s2s_six_node_800_users_ungraceful_node_failure_client_visible_convergence() {
    let _guard = s2s_network_test_guard().await;
    let mut cluster = spawn_s2s_convergence_cluster().await;
    let servers = &cluster.servers;
    println!("node-offline setup: spawned 6 S2S runtimes");

    for (idx, server) in servers.iter().enumerate() {
        server
            .authenticator
            .register_user("observer", None, Some(910_000 + idx as u32), vec![]);
    }
    let mut sessions_by_node = Vec::with_capacity(servers.len());
    for (idx, server) in servers.iter().enumerate() {
        sessions_by_node.push(add_synthetic_published_users(server, (idx + 1) as u16).await);
        println!(
            "node-offline setup: node {} published {} synthetic users",
            idx + 1,
            sessions_by_node[idx].len()
        );
    }
    cluster.connect_full_mesh().await;
    println!("node-offline setup: full mesh addresses installed");
    wait_for_convergence_cluster(&cluster).await;
    println!("node-offline setup: overlay converged");
    assert!(
        wait_for_servers_to_track_users(&servers, &sessions_by_node, Duration::from_secs(45)).await,
        "all servers should materialize all synthetic users before the measured outage"
    );
    let observer = TestClient::connect_and_authenticate(&servers[0], "observer", None)
        .await
        .expect("observer");
    println!("node-offline setup: observer connected");
    assert!(
        wait_for_observer_to_know_users(&observer, &sessions_by_node[5], Duration::from_secs(45))
            .await,
        "observer should receive node 6's initial UserState set before the measured outage"
    );
    observer.drain_now().await;

    let offline_transport = cluster.servers[5]
        .server
        .s2s_manager()
        .transport()
        .expect("node 6 transport");
    let started = Instant::now();
    offline_transport.shutdown().await;

    let elapsed = wait_for_user_removes(&observer, &sessions_by_node[5], Duration::from_secs(45))
        .await
        .unwrap_or_else(|| {
            panic!(
                "observer did not receive all {} UserRemove messages from offline node",
                sessions_by_node[5].len()
            )
        });

    println!(
        "ungraceful-node-failure convergence: observer received {} UserRemove messages in {:?} after node 6 transport shutdown (configured lsa_max_age={}ms)",
        sessions_by_node[5].len(),
        elapsed,
        CONVERGENCE_LSA_MAX_AGE_MS
    );
    assert!(
        started.elapsed() >= elapsed,
        "elapsed timer should be measured from transport shutdown"
    );
}

/// Checks that a failed S2S transport startup does not block the native client
/// listener/runtime. Expected: the S2S actor exits after its own startup error,
/// while a normal client can still authenticate and receive a TCP ping reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_client_connects_when_s2s_transport_startup_fails() {
    let _guard = s2s_network_test_guard().await;
    let pki = Arc::new(mint_pki(&[1]));
    let server = spawn_s2s_test_server_with_config(
        TestServerOpts::default(),
        pki,
        1,
        0,
        S2sConfig {
            enabled: true,
            ..S2sConfig::default()
        },
    )
    .await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice should authenticate even when s2s startup fails");
    let timestamp = 0x52_u64;
    alice
        .send(Ping::default_from_timestamp(timestamp).into())
        .await;

    let response = alice
        .recv_until(
            |m| matches!(m, Message::Ping(p) if p.timestamp == Some(timestamp)),
            CLIENT_DEADLINE,
        )
        .await;
    assert!(
        response.is_some(),
        "native client should receive a TCP ping response after s2s startup failure"
    );

    server.shutdown_gracefully().await;
}

/// Checks client replication after an S2S node restarts while another node's
/// client stays connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_client_replication_recovers_after_node_restart() {
    let _guard = s2s_network_test_guard().await;
    let pki = Arc::new(mint_pki(&[1, 2]));
    let a_s2s_port = pick_free_port().await;
    let b_s2s_port = pick_free_port().await;
    let (a, b) = spawn_s2s_pair_on_ports(Arc::clone(&pki), a_s2s_port, b_s2s_port).await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    wait_for_server_to_track_client(&a, bob.server_session).await;
    wait_for_server_to_track_client(&b, alice.server_session).await;
    assert!(
        client_sees_user_state(&alice, bob.server_session, "bob").await,
        "Alice should initially see Bob"
    );
    assert!(
        client_sees_user_state(&bob, alice.server_session, "alice").await,
        "Bob should initially see Alice"
    );

    let old_bob_session = bob.server_session;
    drop(bob);

    let saw_old_bob_remove = alice
        .recv_until(
            |m| matches!(m, Message::UserRemove(ur) if ur.session == u32::from(old_bob_session)),
            S2S_DEADLINE,
        )
        .await;
    assert!(
        saw_old_bob_remove.is_some(),
        "Alice should see old Bob go offline"
    );

    b.shutdown_gracefully().await;

    let b_restarted_s2s_port = pick_free_port().await;
    let b = spawn_s2s_node_b(Arc::clone(&pki), a_s2s_port, b_restarted_s2s_port).await;
    b.authenticator.register_user("bob", None, Some(2), vec![]);
    wait_for_s2s_pair(&a, &b).await;

    let bob_reconnected = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob reconnect");

    wait_for_server_to_track_client(&a, bob_reconnected.server_session).await;
    wait_for_server_to_track_client(&b, alice.server_session).await;
    assert!(
        client_sees_user_state(&alice, bob_reconnected.server_session, "bob").await,
        "Alice should see Bob after node B restarts"
    );
    assert!(
        client_sees_user_state(&bob_reconnected, alice.server_session, "alice").await,
        "Bob should see Alice after node B restarts"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_client_replication_catches_up_when_second_node_starts_later() {
    let _guard = s2s_network_test_guard().await;
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
    a.authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");

    let b = spawn_s2s_node_b(Arc::clone(&pki), a_s2s_port, b_s2s_port).await;
    b.authenticator.register_user("bob", None, Some(2), vec![]);
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    wait_for_s2s_pair(&a, &b).await;
    wait_for_server_to_track_client(&a, bob.server_session).await;
    wait_for_server_to_track_client(&b, alice.server_session).await;
    assert!(
        client_sees_user_state(&alice, bob.server_session, "bob").await,
        "Alice should see Bob when node B starts later"
    );
    assert!(
        client_sees_user_state(&bob, alice.server_session, "alice").await,
        "Bob should catch up Alice when node B starts later"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_client_replication_catches_up_preexisting_clients_when_node_joins_overlay() {
    let _guard = s2s_network_test_guard().await;
    let pki = Arc::new(mint_pki(&[1, 2, 3]));
    let a_s2s_port = pick_free_port().await;
    let b_s2s_port = pick_free_port().await;
    let c_s2s_port = pick_free_port().await;

    let a = spawn_s2s_test_server_with_config(
        TestServerOpts::default(),
        Arc::clone(&pki),
        1,
        0,
        fast_owner_catchup_s2s_config(
            loopback(a_s2s_port),
            vec![S2sSeedAddressConfig::new(
                S2sTransportKindConfig::Tcp,
                loopback(c_s2s_port),
            )],
        ),
    )
    .await;
    let c = spawn_s2s_test_server_with_config(
        TestServerOpts::default(),
        Arc::clone(&pki),
        3,
        2,
        fast_owner_catchup_s2s_config(
            loopback(c_s2s_port),
            vec![S2sSeedAddressConfig::new(
                S2sTransportKindConfig::Tcp,
                loopback(a_s2s_port),
            )],
        ),
    )
    .await;
    wait_for_s2s_cluster(&[(&a, 1), (&c, 3)]).await;

    a.authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");

    let b = spawn_s2s_test_server_with_config(
        TestServerOpts::default(),
        Arc::clone(&pki),
        2,
        1,
        fast_owner_catchup_s2s_config(loopback(b_s2s_port), Vec::new()),
    )
    .await;
    wait_for_s2s_runtime(&b).await;
    b.authenticator.register_user("bob", None, Some(2), vec![]);
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    assert!(
        !a.server
            .s2s_manager()
            .overlay()
            .expect("A overlay")
            .alive_members()
            .contains(&2),
        "B should not be in the overlay before the test links it"
    );

    add_s2s_peer_address(&a, 2, b_s2s_port).await;
    add_s2s_peer_address(&b, 1, a_s2s_port).await;
    add_s2s_peer_address(&b, 3, c_s2s_port).await;
    add_s2s_peer_address(&c, 2, b_s2s_port).await;
    wait_for_s2s_cluster(&[(&a, 1), (&b, 2), (&c, 3)]).await;

    wait_for_server_to_track_client(&a, bob.server_session).await;
    assert!(
        client_sees_user_state(&alice, bob.server_session, "bob").await,
        "Alice should see Bob after node B joins with Bob already online"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_client_replication_catches_up_with_demo_transport_mix() {
    let _guard = s2s_network_test_guard().await;
    let pki = Arc::new(mint_pki(&[1, 2]));

    let a_tcp = loopback(pick_free_port().await);
    let b_tcp = loopback(pick_free_port().await);
    let a_kcp = loopback(pick_free_udp_port().await);
    let b_kcp = loopback(pick_free_udp_port().await);
    let a_quic = loopback(pick_free_udp_port().await);
    let b_quic = loopback(pick_free_udp_port().await);
    let a_udp = loopback(pick_free_udp_port().await);
    let b_udp = loopback(pick_free_udp_port().await);

    let a = spawn_s2s_test_server_with_config(
        TestServerOpts::default(),
        Arc::clone(&pki),
        1,
        0,
        all_transport_s2s_config(a_tcp, a_kcp, a_quic, a_udp, b_tcp),
    )
    .await;
    a.authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");

    let b = spawn_s2s_test_server_with_config(
        TestServerOpts::default(),
        Arc::clone(&pki),
        2,
        1,
        all_transport_s2s_config(b_tcp, b_kcp, b_quic, b_udp, a_tcp),
    )
    .await;
    b.authenticator.register_user("bob", None, Some(2), vec![]);
    let bob = TestClient::connect_and_authenticate(&b, "bob", None)
        .await
        .expect("bob");

    wait_for_s2s_pair(&a, &b).await;
    wait_for_server_to_track_client(&a, bob.server_session).await;
    wait_for_server_to_track_client(&b, alice.server_session).await;
    assert!(
        client_sees_user_state(&alice, bob.server_session, "bob").await,
        "Alice should see Bob when the later node also advertises KCP/QUIC/UDP"
    );
    assert!(
        client_sees_user_state(&bob, alice.server_session, "alice").await,
        "Bob should catch up Alice when the later node also advertises KCP/QUIC/UDP"
    );
}

/// Checks that a reconnecting client receives other replicated users in their
/// actual channels, even though the reconnecting client itself starts in root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s2s_reconnect_initial_snapshot_preserves_remote_user_channel() {
    let _guard = s2s_network_test_guard().await;
    let (a, b) = spawn_s2s_pair().await;
    wait_for_s2s_pair(&a, &b).await;
    register_pair_users(&a, &b);

    a.server
        .get_channels()
        .create_channel(shitspeak_state::Channel::new(
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
        Some(42),
        "Bob reconnects into last-channel"
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
    let _guard = s2s_network_test_guard().await;
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
