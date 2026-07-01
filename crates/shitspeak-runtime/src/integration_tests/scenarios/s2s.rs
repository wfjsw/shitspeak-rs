//! S2S-enabled server scenarios.

pub mod application;
pub mod overlay;
pub mod replications;
pub mod transport;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::ban_repository::{BanEntry, BanOp};
use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::config::{S2sConfig, S2sSeedAddressConfig, S2sTransportKindConfig};
use crate::integration_tests::harness::{
    TestClient, TestS2sServerOpts, TestServer, TestServerOpts, spawn_s2s_test_server,
    spawn_s2s_test_server_with_config,
};
use crate::messages::Message;
use crate::messages::encoder::{Ping, PluginDataTransmission, TextMessage, UserStats};
use crate::voice::codec::AudioPayload;
use shitspeak_s2s::testing::{
    LinkChaos, Pki, loopback, mint_pki, pick_free_port, pick_free_udp_port, s2s_network_test_guard,
    wait_until,
};
use shitspeak_s2s_transport::{PeerAddress, ServiceLevel, TransportKind};

const S2S_DEADLINE: Duration = Duration::from_secs(10);
const CLIENT_DEADLINE: Duration = Duration::from_secs(4);
const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
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

async fn wait_for_s2s_cluster(nodes: &[(&TestServer, u16)]) {
    let ready = wait_until(S2S_DEADLINE, || {
        nodes.iter().all(|(server, node_id)| {
            let mgr = server.server.s2s_manager();
            let Some(overlay) = mgr.overlay() else {
                return false;
            };
            mgr.application().is_some()
                && mgr.replications().is_some()
                && nodes.iter().all(|(_, peer_id)| {
                    node_id == peer_id
                        || (overlay.alive_members().contains(peer_id)
                            && overlay.route_to(*peer_id, ServiceLevel::Reliable).is_some())
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
        .any(|us| us.session == Some(session) && us.name.as_deref() == Some(name))
        || client
            .recv_until(
                |m| {
                    matches!(m, Message::UserState(us)
                        if us.session == Some(session) && us.name.as_deref() == Some(name))
                },
                S2S_DEADLINE,
            )
            .await
            .is_some()
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
    let _guard = s2s_network_test_guard().await;
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
        .create_channel(crate::channels::Channel::new(
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
        .create_channel(crate::channels::Channel::new(
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
        .create_channel(crate::channels::Channel::new(
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
                && state.name.as_deref() == Some("bob")
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
                            && state.name.as_deref() == Some("bob") =>
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

    let bob_session = bob.server_session;
    let bob_session_wire = u32::from(bob_session);
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

    let saw_reverse_add = alice
        .initial_user_states
        .iter()
        .any(|us| us.session == Some(bob_session_wire) && us.name.as_deref() == Some("bob"))
        || alice
            .recv_until(
                |m| {
                    matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session_wire)
                        && us.name.as_deref() == Some("bob"))
                },
                S2S_DEADLINE,
            )
            .await
            .is_some();
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

    let diagnostic_channel = crate::channels::Channel::new(
        S2S_LAG_DIAGNOSTIC_CHANNEL_ID,
        "Lag Diagnostic",
        0,
        0,
        Some(0),
    );
    let diagnostic_channel_op = crate::channel_repository::ChannelOp::CreateChannel {
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

    let a = spawn_s2s_test_server(
        TestServerOpts::default(),
        Arc::clone(&pki),
        TestS2sServerOpts {
            node_id: 1,
            cert_index: 0,
            tcp_listen: loopback(a_s2s_port),
            seed_addresses: vec![S2sSeedAddressConfig::new(
                S2sTransportKindConfig::Tcp,
                loopback(c_s2s_port),
            )],
        },
    )
    .await;
    let c = spawn_s2s_test_server(
        TestServerOpts::default(),
        Arc::clone(&pki),
        TestS2sServerOpts {
            node_id: 3,
            cert_index: 2,
            tcp_listen: loopback(c_s2s_port),
            seed_addresses: vec![S2sSeedAddressConfig::new(
                S2sTransportKindConfig::Tcp,
                loopback(a_s2s_port),
            )],
        },
    )
    .await;
    wait_for_s2s_cluster(&[(&a, 1), (&c, 3)]).await;

    a.authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    let alice = TestClient::connect_and_authenticate(&a, "alice", None)
        .await
        .expect("alice");

    let b = spawn_s2s_test_server(
        TestServerOpts::default(),
        Arc::clone(&pki),
        TestS2sServerOpts {
            node_id: 2,
            cert_index: 1,
            tcp_listen: loopback(b_s2s_port),
            seed_addresses: Vec::new(),
        },
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
