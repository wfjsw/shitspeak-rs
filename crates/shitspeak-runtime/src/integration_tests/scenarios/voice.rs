//! Voice routing scenarios.
//!
//! Each scenario exists in two flavors: TCP-tunneled (sender writes
//! `Message::UDPTunnel`, server fans out to the per-recipient TCP voice
//! queue) and real UDP (sender encrypts with OCB2 and sends via a UDP
//! socket; recipient receives, decrypts, decodes).

use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{
    future::join_all,
    stream::{FuturesUnordered, StreamExt},
};
use parking_lot::Mutex as ParkingMutex;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use serde::Deserialize;

use crate::acl::ACLPermissions;
use crate::channels::Channel;
use crate::constants::PROTOBUF_INTRODUCED_VERSION;
use crate::integration_tests::harness::{
    TestClient, TestServer, TestServerOpts, spawn_test_server, test_client::ConnectError,
};
use crate::messages::Message;
use crate::messages::encoder::{AudioTarget, ChanAcl, Ping, UserState, VoiceTarget};
use crate::mumble_proto::voice_target::Target as VoiceTargetEntry;
use crate::protocol_version::ProtocolVersion;
use crate::voice::codec::{AudioPayload, PacketFormat};
use crate::voice::metrics::{
    VoiceRouteKind, VoiceRouteSource, route_metric_snapshot, route_resolution_metric_snapshot,
};

const VOICE_DEADLINE: Duration = Duration::from_secs(2);
const NEGATIVE_WINDOW: Duration = Duration::from_millis(500);
const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
const LARGE_TREE_SERVER_BRANCHES: usize = 2;
const LARGE_TREE_CLIENTS_PER_BRANCH: usize = 500;
const LARGE_TREE_CLIENTS: usize = LARGE_TREE_SERVER_BRANCHES * LARGE_TREE_CLIENTS_PER_BRANCH;
const LARGE_TREE_SEED: u64 = 0x5771_7EC0;
const LARGE_TREE_NEGATIVE_SAMPLE: usize = 40;
const LARGE_TREE_CONNECT_DEADLINE: Duration = Duration::from_secs(600);
const LARGE_TREE_CONNECT_ATTEMPT_DEADLINE: Duration = Duration::from_secs(60);
const LARGE_TREE_CONNECT_ATTEMPTS: usize = 3;
const LARGE_TREE_AUTHENTICATE_TIMEOUT_MS: u64 = 600_000;
const LARGE_TREE_AUTH_FINALIZATION_CONCURRENCY: usize = 64;
const LARGE_TREE_STREAM_BARRIER_DEADLINE: Duration = Duration::from_secs(30);
const LARGE_TREE_SEGMENT_FRAMES: usize = 501;
const LARGE_TREE_FRAME_INTERVAL: Duration = Duration::from_millis(20);
const LARGE_TREE_MIN_SPEAK_SPAN: Duration = Duration::from_secs(10);
const LARGE_TREE_FRAME_LATENCY_BUDGET: Duration = Duration::from_secs(2);
const LARGE_TREE_END_TO_END_LATENCY_BUDGET: Duration = Duration::from_secs(2);
const LARGE_TREE_CPU_CORE_BUDGET: f64 = 0.40;
const LARGE_TREE_CPU_SPIKE_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const LARGE_TREE_OPUS_FRAME: &[u8] = SAMPLE_OPUS;

fn opus_frame(payload: &AudioPayload) -> &[u8] {
    match payload {
        AudioPayload::Opus(p) => &p.frame,
        _ => panic!("expected Opus payload, got {payload:?}"),
    }
}

fn voice_target(slot: u32, targets: Vec<VoiceTargetEntry>) -> VoiceTarget {
    VoiceTarget {
        id: Some(slot),
        targets,
    }
}

fn voice_target_user(session: u32) -> VoiceTargetEntry {
    VoiceTargetEntry {
        session: vec![session],
        channel_id: None,
        group: None,
        links: Some(false),
        children: Some(false),
    }
}

fn voice_target_channel(
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

async fn expect_voice_from(recipient: &TestClient, sender: &TestClient, reason: &str) {
    let audio = recipient
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect(reason);
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(sender.server_session));
}

async fn expect_no_voice(recipient: &TestClient, reason: &str) {
    assert!(
        recipient.recv_voice_tcp(NEGATIVE_WINDOW).await.is_none(),
        "{reason}"
    );
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

#[derive(Clone, Deserialize)]
struct LargeTreeChannelSpec {
    id: u32,
    parent_id: Option<u32>,
    name: String,
    position: i32,
    max_users: u32,
    links: Vec<u32>,
}

struct LargeTreeClient {
    client: TestClient,
    channel_id: u32,
    in_casters: bool,
}

struct LargeTreeShoutCase {
    slot: u32,
    target_channel: u32,
    children: bool,
    links: bool,
    group: Option<&'static str>,
    frame: u64,
    label: &'static str,
}

#[derive(Deserialize)]
struct LargeTreeFixture {
    channels: Vec<LargeTreeChannelSpec>,
}

fn large_tree_channel_specs() -> Vec<LargeTreeChannelSpec> {
    serde_json::from_str::<LargeTreeFixture>(include_str!("../fixtures/large_channel_tree.json"))
        .expect("large channel tree fixture should parse")
        .channels
}

fn large_tree_channel_tree(specs: &[LargeTreeChannelSpec]) -> HashMap<u32, Vec<u32>> {
    let mut tree: HashMap<u32, Vec<u32>> = HashMap::new();
    for spec in specs {
        if let Some(parent_id) = spec.parent_id {
            tree.entry(parent_id).or_default().push(spec.id);
        }
        tree.entry(spec.id).or_default();
    }
    tree
}

fn large_tree_subtree_ids(tree: &HashMap<u32, Vec<u32>>, root: u32) -> HashSet<u32> {
    let mut out = HashSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !out.insert(id) {
            continue;
        }
        if let Some(children) = tree.get(&id) {
            stack.extend(children.iter().copied());
        }
    }
    out
}

fn large_tree_link_groups(specs: &[LargeTreeChannelSpec]) -> Vec<Vec<u32>> {
    let mut adjacency: HashMap<u32, HashSet<u32>> = HashMap::new();
    for spec in specs {
        adjacency.entry(spec.id).or_default();
        for &linked_id in &spec.links {
            adjacency.entry(spec.id).or_default().insert(linked_id);
            adjacency.entry(linked_id).or_default().insert(spec.id);
        }
    }

    let mut seen = HashSet::new();
    let mut groups = Vec::new();
    for &start in adjacency.keys() {
        if !seen.insert(start) {
            continue;
        }
        let mut group = Vec::new();
        let mut stack = vec![start];
        while let Some(id) = stack.pop() {
            group.push(id);
            if let Some(neighbors) = adjacency.get(&id) {
                for &neighbor in neighbors {
                    if seen.insert(neighbor) {
                        stack.push(neighbor);
                    }
                }
            }
        }
        if group.len() > 1 {
            group.sort_unstable();
            groups.push(group);
        }
    }
    groups.sort_by_key(|group| (std::cmp::Reverse(group.len()), group[0]));
    groups
}

fn large_tree_target_channels(
    tree: &HashMap<u32, Vec<u32>>,
    link_groups: &[Vec<u32>],
    case: &LargeTreeShoutCase,
) -> HashSet<u32> {
    let mut channels = if case.children {
        large_tree_subtree_ids(tree, case.target_channel)
    } else {
        HashSet::from([case.target_channel])
    };

    if case.links {
        let initial: Vec<u32> = channels.iter().copied().collect();
        for group in link_groups {
            if group.iter().any(|id| initial.contains(id)) {
                channels.extend(group.iter().copied());
            }
        }
    }

    channels
}

fn large_tree_expected_recipients(
    clients: &[LargeTreeClient],
    tree: &HashMap<u32, Vec<u32>>,
    link_groups: &[Vec<u32>],
    case: &LargeTreeShoutCase,
) -> HashSet<usize> {
    let target_channels = large_tree_target_channels(tree, link_groups, case);
    clients
        .iter()
        .enumerate()
        .filter(|(_, client)| {
            target_channels.contains(&client.channel_id)
                && case
                    .group
                    .map_or(true, |group| group == "casters" && client.in_casters)
        })
        .map(|(idx, _)| idx)
        .collect()
}

fn large_tree_root_id(specs: &[LargeTreeChannelSpec]) -> u32 {
    specs
        .iter()
        .find(|spec| spec.parent_id.is_none())
        .expect("fixture has root")
        .id
}

fn large_tree_leaves_under(tree: &HashMap<u32, Vec<u32>>, root: u32) -> Vec<u32> {
    let mut leaves = Vec::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        match tree.get(&id) {
            Some(children) if !children.is_empty() => {
                stack.extend(children.iter().copied());
            }
            _ => leaves.push(id),
        }
    }
    leaves.sort_unstable();
    leaves
}

fn large_tree_server_roots(
    specs: &[LargeTreeChannelSpec],
    tree: &HashMap<u32, Vec<u32>>,
    count: usize,
) -> Vec<u32> {
    let root_id = large_tree_root_id(specs);
    let mut roots = tree
        .get(&root_id)
        .expect("fixture root has top-level branches")
        .iter()
        .filter(|id| !large_tree_leaves_under(tree, **id).is_empty())
        .copied()
        .collect::<Vec<_>>();
    roots.sort_by_key(|id| {
        (
            std::cmp::Reverse(large_tree_subtree_ids(tree, *id).len()),
            *id,
        )
    });
    roots.truncate(count);
    assert_eq!(
        roots.len(),
        count,
        "fixture does not have enough top-level branches"
    );
    roots
}

fn deepest_descendant_or_self(tree: &HashMap<u32, Vec<u32>>, root: u32) -> u32 {
    let mut best = root;
    let mut stack = vec![(root, 0usize)];
    while let Some((id, depth)) = stack.pop() {
        let best_depth = distance_from_root(tree, root, best);
        if depth > best_depth || (depth == best_depth && id < best) {
            best = id;
        }
        if let Some(children) = tree.get(&id) {
            stack.extend(children.iter().copied().map(|child| (child, depth + 1)));
        }
    }
    best
}

fn distance_from_root(tree: &HashMap<u32, Vec<u32>>, root: u32, target: u32) -> usize {
    let mut stack = vec![(root, 0usize)];
    while let Some((id, depth)) = stack.pop() {
        if id == target {
            return depth;
        }
        if let Some(children) = tree.get(&id) {
            stack.extend(children.iter().copied().map(|child| (child, depth + 1)));
        }
    }
    0
}

fn large_tree_shout_cases(
    tree: &HashMap<u32, Vec<u32>>,
    link_groups: &[Vec<u32>],
    server_roots: &[u32],
) -> Vec<LargeTreeShoutCase> {
    let selected_channels = server_roots
        .iter()
        .flat_map(|root| large_tree_subtree_ids(tree, *root))
        .collect::<HashSet<_>>();
    let exact = *large_tree_leaves_under(tree, server_roots[0])
        .first()
        .expect("selected branch has leaves");
    let recursive = server_roots[0];
    let linked = link_groups
        .iter()
        .find(|group| group.iter().any(|id| selected_channels.contains(id)))
        .and_then(|group| group.iter().find(|id| selected_channels.contains(id)))
        .copied()
        .expect("selected branches have linked channels");
    let recursive_linked = server_roots
        .iter()
        .find(|root| {
            let subtree = large_tree_subtree_ids(tree, **root);
            link_groups
                .iter()
                .any(|group| group.iter().any(|id| subtree.contains(id)))
        })
        .copied()
        .unwrap_or(recursive);
    let second_recursive = server_roots.get(1).copied();

    let mut cases = vec![
        LargeTreeShoutCase {
            slot: 7,
            target_channel: exact,
            children: false,
            links: false,
            group: None,
            frame: 500,
            label: "exact leaf channel",
        },
        LargeTreeShoutCase {
            slot: 8,
            target_channel: recursive,
            children: true,
            links: false,
            group: None,
            frame: 600,
            label: "recursive production branch",
        },
        LargeTreeShoutCase {
            slot: 9,
            target_channel: linked,
            children: false,
            links: true,
            group: None,
            frame: 700,
            label: "linked production channels",
        },
        LargeTreeShoutCase {
            slot: 10,
            target_channel: recursive_linked,
            children: true,
            links: true,
            group: None,
            frame: 800,
            label: "recursive linked production branch",
        },
        LargeTreeShoutCase {
            slot: 11,
            target_channel: recursive_linked,
            children: true,
            links: true,
            group: Some("casters"),
            frame: 900,
            label: "caster-only recursive linked production branch",
        },
    ];
    if let Some(second_recursive) = second_recursive {
        cases.push(LargeTreeShoutCase {
            slot: 12,
            target_channel: second_recursive,
            children: true,
            links: false,
            group: None,
            frame: 1000,
            label: "recursive second production branch",
        });
    }
    cases
}

async fn drain_large_tree_clients_until_quiet(alice: &TestClient, clients: &[LargeTreeClient]) {
    let mut quiet_ticks = 0usize;
    for _ in 0..200 {
        let mut drained = alice.drain_now().await.len();
        for client in clients {
            drained += client.client.drain_now().await.len();
        }
        if drained == 0 {
            quiet_ticks += 1;
            if quiet_ticks >= 8 {
                return;
            }
        } else {
            quiet_ticks = 0;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn sync_large_tree_test_client_stream(client: &TestClient, timestamp: u64, label: &str) {
    client
        .send(Ping::default_from_timestamp(timestamp).into())
        .await;
    client
        .recv_until(
            |message| matches!(message, Message::Ping(ping) if ping.timestamp == Some(timestamp)),
            LARGE_TREE_STREAM_BARRIER_DEADLINE,
        )
        .await
        .unwrap_or_else(|| panic!("large-tree stream barrier timed out for {label}"));
}

async fn wait_for_large_tree_clients_indexed(
    server: &crate::integration_tests::harness::TestServer,
    clients: &[LargeTreeClient],
) {
    let repo = server.server.get_clients();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut indexed = HashSet::new();
        let target_channels: HashSet<u32> =
            clients.iter().map(|client| client.channel_id).collect();
        for channel_id in target_channels {
            for client in repo.get_local_clients_in_channel(channel_id).await {
                indexed.insert(u32::from(client.get_session_id()));
            }
        }

        let missing = clients
            .iter()
            .filter(|client| !indexed.contains(&u32::from(client.client.server_session)))
            .count();
        if missing == 0 {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{missing} large-tree clients were not indexed in assigned channels"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn connect_large_tree_load_client(
    server: &TestServer,
    username: &str,
) -> Result<TestClient, ConnectError> {
    let mut last_error = None;
    for attempt in 1..=LARGE_TREE_CONNECT_ATTEMPTS {
        match TestClient::connect_and_authenticate_with_deadline(
            server,
            username,
            None,
            LARGE_TREE_CONNECT_ATTEMPT_DEADLINE,
        )
        .await
        {
            Ok(client) => {
                if attempt > 1 {
                    eprintln!(
                        "large_tree_connect username={} recovered_on_attempt={}",
                        username, attempt
                    );
                }
                return Ok(client);
            }
            Err(error) => {
                eprintln!(
                    "large_tree_connect username={} attempt={} failed={:?}",
                    username, attempt, error
                );
                last_error = Some(error);
                if attempt < LARGE_TREE_CONNECT_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or(ConnectError::NoServerSync))
}

struct LargeTreeClientDelivery {
    first_at: Instant,
    last_at: Instant,
    max_frame_gap: Duration,
}

async fn send_and_assert_large_tree_shout_delivery(
    alice: &TestClient,
    clients: &[LargeTreeClient],
    expected: &HashSet<usize>,
    case: &LargeTreeShoutCase,
    frames: &[(u64, Bytes)],
) {
    let speak_start = Instant::now();
    let route_sample = RouteResourceSample::capture_target();
    let send_task = async {
        let resource_sample = SpeakResourceSample::capture();
        send_large_tree_voice_segment(alice, case, frames).await;
        let send_end = Instant::now();
        let resources = resource_sample.finish().await;
        (send_end, resources)
    };
    let receive_task = async {
        let mut expected_indices = expected.iter().copied().collect::<Vec<_>>();
        expected_indices.sort_unstable();
        join_all(expected_indices.iter().map(|&idx| async move {
            let mut first_at = None;
            let mut last_at = None;
            let mut previous_frame = None;
            let mut previous_receive_at = None;
            let mut max_frame_gap = Duration::from_millis(0);
            for (frame_number, payload) in frames {
                let audio = clients[idx]
                    .client
                    .recv_voice_tcp(LARGE_TREE_FRAME_LATENCY_BUDGET)
                    .await
                    .unwrap_or_else(|| {
                        panic!(
                            "{}: client {idx} should receive frame {frame_number}",
                            case.label
                        )
                    });
                let received_at = Instant::now();
                if first_at.is_none() {
                    first_at = Some(received_at);
                }
                if let Some(previous_receive_at) = previous_receive_at {
                    max_frame_gap =
                        max_frame_gap.max(received_at.duration_since(previous_receive_at));
                }
                previous_receive_at = Some(received_at);

                assert_eq!(audio.sender_session, Some(alice.server_session));
                assert_eq!(
                    audio.frame_number, *frame_number,
                    "{}: client {idx} received a non-contiguous frame",
                    case.label
                );
                assert_eq!(
                    opus_frame(&audio.audio_payload),
                    payload.as_ref(),
                    "{}: client {idx} received corrupted voice payload",
                    case.label
                );
                if let Some(previous_frame) = previous_frame {
                    assert_eq!(
                        *frame_number,
                        previous_frame + 1,
                        "{}: generated segment frames must be contiguous",
                        case.label
                    );
                }
                previous_frame = Some(*frame_number);
                last_at = Some(received_at);
            }
            LargeTreeClientDelivery {
                first_at: first_at.expect("large-tree delivery should include at least one frame"),
                last_at: last_at.expect("large-tree delivery should include at least one frame"),
                max_frame_gap,
            }
        }))
        .await
    };

    let ((send_end, resources), deliveries) = tokio::join!(send_task, receive_task);
    let route_resources = route_sample.finish();
    let max_first_frame_latency = deliveries
        .iter()
        .map(|delivery| delivery.first_at.duration_since(speak_start))
        .max()
        .unwrap_or_default();
    let last_at = deliveries
        .iter()
        .map(|delivery| delivery.last_at)
        .max()
        .unwrap_or(send_end);
    let tail_latency = last_at.saturating_duration_since(send_end);
    let max_frame_gap = deliveries
        .iter()
        .map(|delivery| delivery.max_frame_gap)
        .max()
        .unwrap_or_default();
    let budget = large_tree_cpu_core_budget();
    let route_busy_cores = route_busy_cores(route_resources.resolution_duration(), resources.wall)
        .expect("large-tree speak duration should be non-zero");
    eprintln!(
        "large_tree_speak_metrics case={} recipients={} frames={} routed_frames={} send_ms={} first_latency_ms={} tail_latency_ms={} max_gap_ms={} route_resolution_ms={} route_total_ms={} route_busy_cores={:.2} process_cpu_ms={} process_avg_cores={} process_max_interval_cores={} routing_budget_cores={:.2}",
        case.label,
        expected.len(),
        frames.len(),
        route_resources.frames(),
        resources.wall.as_millis(),
        max_first_frame_latency.as_millis(),
        tail_latency.as_millis(),
        max_frame_gap.as_millis(),
        route_resources.resolution_duration().as_millis(),
        route_resources.total_duration().as_millis(),
        route_busy_cores,
        resources.cpu.unwrap_or_default().as_millis(),
        resources
            .average_cpu_cores()
            .map(|cores| format!("{cores:.2}"))
            .unwrap_or_else(|| "unavailable".to_owned()),
        resources
            .max_interval_cores
            .map(|cores| format!("{cores:.2}"))
            .unwrap_or_else(|| "unavailable".to_owned()),
        budget
    );

    assert!(
        max_first_frame_latency <= LARGE_TREE_END_TO_END_LATENCY_BUDGET,
        "{}: first voice frame latency was {:?}, expected <= {:?}",
        case.label,
        max_first_frame_latency,
        LARGE_TREE_END_TO_END_LATENCY_BUDGET
    );
    assert!(
        tail_latency <= LARGE_TREE_END_TO_END_LATENCY_BUDGET,
        "{}: voice segment tail latency was {:?}, expected <= {:?}",
        case.label,
        tail_latency,
        LARGE_TREE_END_TO_END_LATENCY_BUDGET
    );
    assert!(
        max_frame_gap <= LARGE_TREE_FRAME_LATENCY_BUDGET,
        "{}: voice stream had a receive gap of {:?}, expected <= {:?}",
        case.label,
        max_frame_gap,
        LARGE_TREE_FRAME_LATENCY_BUDGET
    );

    assert!(
        route_resources.frames() >= frames.len() as u64,
        "{}: expected at least {} routed target frames, saw {}",
        case.label,
        frames.len(),
        route_resources.frames()
    );
    assert!(
        route_busy_cores <= budget,
        "{}: server voice routing resolution used {:.2} busy cores over {:?}, budget {:.2}",
        case.label,
        route_busy_cores,
        resources.wall,
        budget
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut checked = 0usize;
    for (idx, client) in clients.iter().enumerate() {
        if expected.contains(&idx) {
            continue;
        }
        assert!(
            client
                .client
                .recv_voice_tcp(Duration::from_millis(25))
                .await
                .is_none(),
            "{}: client {idx} in channel {} should not receive shout",
            case.label,
            client.channel_id
        );
        checked += 1;
        if checked >= LARGE_TREE_NEGATIVE_SAMPLE {
            break;
        }
    }
    assert!(
        checked > 0,
        "{} should leave at least one non-recipient to sample",
        case.label
    );
}

async fn wait_for_voice_target_installed(
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
            "voice target slot {slot} was not installed before shout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn large_tree_voice_segment(case: &LargeTreeShoutCase) -> Vec<(u64, Bytes)> {
    (0..LARGE_TREE_SEGMENT_FRAMES)
        .map(|offset| {
            let frame_number = case.frame + offset as u64;
            let payload = Bytes::from_static(LARGE_TREE_OPUS_FRAME);
            (frame_number, payload)
        })
        .collect()
}

fn large_tree_segment_send_span(frames: &[(u64, Bytes)]) -> Duration {
    let intervals = frames.len().saturating_sub(1) as u32;
    LARGE_TREE_FRAME_INTERVAL * intervals
}

async fn send_large_tree_voice_segment(
    alice: &TestClient,
    case: &LargeTreeShoutCase,
    frames: &[(u64, Bytes)],
) {
    for (idx, (frame_number, payload)) in frames.iter().enumerate() {
        alice
            .send_voice_tcp(case.slot, *frame_number, payload.clone())
            .await;
        if idx + 1 < frames.len() {
            tokio::time::sleep(LARGE_TREE_FRAME_INTERVAL).await;
        }
    }
}

struct SpeakResourceSample {
    wall: Instant,
    cpu: Option<Duration>,
    spike_probe: Option<CpuSpikeProbe>,
}

impl SpeakResourceSample {
    fn capture() -> Self {
        Self {
            wall: Instant::now(),
            cpu: process_cpu_time(),
            spike_probe: CpuSpikeProbe::start(),
        }
    }

    async fn finish(self) -> SpeakResourceMeasurement {
        let wall = self.wall.elapsed();
        let cpu = self.cpu.and_then(|start| {
            process_cpu_time().map(|end| end.checked_sub(start).unwrap_or_default())
        });
        let max_interval_cores = match self.spike_probe {
            Some(probe) => probe.finish().await,
            None => None,
        };
        SpeakResourceMeasurement {
            wall,
            cpu,
            max_interval_cores,
        }
    }
}

struct SpeakResourceMeasurement {
    wall: Duration,
    cpu: Option<Duration>,
    max_interval_cores: Option<f64>,
}

impl SpeakResourceMeasurement {
    fn average_cpu_cores(&self) -> Option<f64> {
        let wall_secs = self.wall.as_secs_f64();
        if wall_secs <= f64::EPSILON {
            return None;
        }
        self.cpu.map(|cpu| cpu.as_secs_f64() / wall_secs)
    }
}

struct RouteResourceSample {
    total_before: crate::voice::metrics::VoiceRouteMetricSnapshot,
    resolution_before: crate::voice::metrics::VoiceRouteMetricSnapshot,
}

impl RouteResourceSample {
    fn capture_target() -> Self {
        Self {
            total_before: route_metric_snapshot(VoiceRouteSource::Local, VoiceRouteKind::Target),
            resolution_before: route_resolution_metric_snapshot(
                VoiceRouteSource::Local,
                VoiceRouteKind::Target,
            ),
        }
    }

    fn finish(self) -> RouteResourceMeasurement {
        let total = route_metric_snapshot(VoiceRouteSource::Local, VoiceRouteKind::Target)
            .saturating_sub(self.total_before);
        let resolution =
            route_resolution_metric_snapshot(VoiceRouteSource::Local, VoiceRouteKind::Target)
                .saturating_sub(self.resolution_before);
        RouteResourceMeasurement { total, resolution }
    }
}

struct RouteResourceMeasurement {
    total: crate::voice::metrics::VoiceRouteMetricSnapshot,
    resolution: crate::voice::metrics::VoiceRouteMetricSnapshot,
}

impl RouteResourceMeasurement {
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

fn route_busy_cores(route_duration: Duration, wall: Duration) -> Option<f64> {
    let wall_secs = wall.as_secs_f64();
    if wall_secs <= f64::EPSILON {
        return None;
    }
    Some(route_duration.as_secs_f64() / wall_secs)
}

struct CpuSpikeProbe {
    stop: Arc<AtomicBool>,
    max_cores: Arc<ParkingMutex<f64>>,
    handle: tokio::task::JoinHandle<()>,
}

impl CpuSpikeProbe {
    fn start() -> Option<Self> {
        let initial_cpu = process_cpu_time()?;
        let stop = Arc::new(AtomicBool::new(false));
        let max_cores = Arc::new(ParkingMutex::new(0.0));
        let task_stop = Arc::clone(&stop);
        let task_max_cores = Arc::clone(&max_cores);
        let handle = tokio::spawn(async move {
            let mut previous_cpu = initial_cpu;
            let mut previous_wall = Instant::now();
            while !task_stop.load(Ordering::Relaxed) {
                tokio::time::sleep(LARGE_TREE_CPU_SPIKE_SAMPLE_INTERVAL).await;
                let Some(current_cpu) = process_cpu_time() else {
                    continue;
                };
                let current_wall = Instant::now();
                let wall = current_wall.duration_since(previous_wall);
                if wall.as_secs_f64() > f64::EPSILON {
                    let cpu = current_cpu
                        .checked_sub(previous_cpu)
                        .unwrap_or_default()
                        .as_secs_f64();
                    let cores = cpu / wall.as_secs_f64();
                    let mut max = task_max_cores.lock();
                    if cores > *max {
                        *max = cores;
                    }
                }
                previous_cpu = current_cpu;
                previous_wall = current_wall;
            }
        });
        Some(Self {
            stop,
            max_cores,
            handle,
        })
    }

    async fn finish(self) -> Option<f64> {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.handle.await;
        Some(*self.max_cores.lock())
    }
}

fn large_tree_cpu_core_budget() -> f64 {
    LARGE_TREE_CPU_CORE_BUDGET
}

#[cfg(unix)]
fn process_cpu_time() -> Option<Duration> {
    unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return None;
        }
        Some(timeval_duration(usage.ru_utime) + timeval_duration(usage.ru_stime))
    }
}

#[cfg(unix)]
fn timeval_duration(value: libc::timeval) -> Duration {
    Duration::from_secs(value.tv_sec as u64) + Duration::from_micros(value.tv_usec as u64)
}

#[cfg(windows)]
fn process_cpu_time() -> Option<Duration> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    unsafe {
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = creation;
        let mut kernel = creation;
        let mut user = creation;
        if GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        ) == 0
        {
            return None;
        }

        let kernel_ticks = filetime_100ns_ticks(kernel);
        let user_ticks = filetime_100ns_ticks(user);
        Some(Duration::from_nanos(
            kernel_ticks.saturating_add(user_ticks).saturating_mul(100),
        ))
    }
}

#[cfg(windows)]
fn filetime_100ns_ticks(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

#[cfg(not(any(unix, windows)))]
fn process_cpu_time() -> Option<Duration> {
    None
}

// ── TCP-tunneled tests ──────────────────────────────────────────────────────

/// Checks regular TCP-tunneled voice routing within one channel.
/// Expected: Bob receives Alice's Opus payload with Alice's server session as
/// sender. Mumble routes `UDPTunnel` audio through `D:\mumble\src\murmur\Server.cpp::processMsg`;
/// shitspeak mirrors regular voice broadcast in `D:\shitspeak\client.go` and
/// `D:\shitspeak\message.go`.
#[tokio::test]
async fn voice_tcp_same_channel_routes() {
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

    alice
        .send_voice_tcp(0, 1, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let received = bob.recv_voice_tcp(VOICE_DEADLINE).await;
    let audio = received.expect("Bob should receive Alice's voice over TCP tunnel");
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
}

/// Checks that regular voice is not routed to users in unrelated channels.
/// Expected: after Bob moves to another channel, he receives no TCP-tunneled
/// voice from Alice. This comes from Mumble's channel-scoped receiver selection
/// in `D:\mumble\src\murmur\Server.cpp::processMsg` and shitspeak's voice
/// target selection in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_tcp_different_channel_does_not_route() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(50, "Lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(50).await;
    // Wait for the move to take effect on the server side.
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .send_voice_tcp(0, 2, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let received = bob.recv_voice_tcp(NEGATIVE_WINDOW).await;
    assert!(
        received.is_none(),
        "Bob in a different channel should NOT receive Alice's voice"
    );
}

/// Checks that self-muted users cannot send voice.
/// Expected: Bob receives no audio from Alice while Alice has `self_mute`.
/// Mumble drops muted/self-muted senders at the top of
/// `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak applies the same
/// sender gate in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_tcp_self_mute_silences_sender() {
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

    alice.set_self_mute(true).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    alice
        .send_voice_tcp(0, 3, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let received = bob.recv_voice_tcp(NEGATIVE_WINDOW).await;
    assert!(
        received.is_none(),
        "Bob should NOT receive voice while Alice is self-muted"
    );
}

/// Checks that self-deafened users do not receive voice.
/// Expected: Bob receives no audio from Alice while Bob has `self_deaf`.
#[tokio::test]
async fn voice_tcp_self_deaf_silences_recipient() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.set_self_deaf(true).await;
    let bob_session = bob.session_id;
    let observed = alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.self_deaf == Some(true))
            },
            VOICE_DEADLINE,
        )
        .await;
    assert!(
        observed.is_some(),
        "Alice should observe Bob becoming self-deafened before voice is sent"
    );

    alice
        .send_voice_tcp(0, 6, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_no_voice(&bob, "Bob should NOT receive voice while self-deafened").await;
}

/// Checks that server-muted users cannot send voice.
/// Expected: Alice receives no audio from Bob after Alice sets Bob's server
/// mute. Mumble's `processMsg` returns for `bMute`, and shitspeak's voice path
/// checks the corresponding `Mute` state in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_tcp_server_mute_silences_sender() {
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

    let bob_session = bob.session_id;
    alice.mute_other(bob_session, true).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    bob.send_voice_tcp(0, 4, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let received = alice.recv_voice_tcp(NEGATIVE_WINDOW).await;
    assert!(
        received.is_none(),
        "Alice should NOT receive voice from server-muted Bob"
    );
}

/// Checks that server-deafened users do not receive voice.
/// Expected: Bob receives no audio from Alice after Alice sets Bob's server
/// deaf state.
#[tokio::test]
async fn voice_tcp_server_deaf_silences_recipient() {
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

    let bob_session = bob.session_id;
    alice.deaf_other(bob_session, true).await;
    let observed = bob
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(bob_session) && us.deaf == Some(true))
            },
            VOICE_DEADLINE,
        )
        .await;
    assert!(
        observed.is_some(),
        "Bob should observe being server-deafened before voice is sent"
    );

    alice
        .send_voice_tcp(0, 7, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_no_voice(&bob, "Bob should NOT receive voice while server-deafened").await;
}

/// Checks that regular speech crosses effective linked-channel groups.
/// Expected: Bob receives Alice's normal-channel voice through a link chain.
/// Mumble explicitly walks linked channels with Speak permission in
/// `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak exposes the same
/// linked-channel voice-target behavior through `D:\shitspeak\voicetarget.go`.
#[tokio::test]
async fn voice_tcp_linked_channel_routes() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(70, "Lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(71, "Side".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans.add_link(0, 70).await.unwrap();
    chans.add_link(70, 71).await.unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(71).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .send_voice_tcp(0, 5, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let received = bob.recv_voice_tcp(VOICE_DEADLINE).await;
    let audio = received.expect(
        "Bob in a transitively linked channel should receive Alice's voice over TCP tunnel",
    );
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
}

/// Checks direct-user voice targets.
/// Expected: only the targeted session receives the packet.
#[tokio::test]
async fn voice_target_to_user_whispers_only_to_that_session() {
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
        .create_channel(Channel::new(90, "WhisperTarget".to_owned(), 0, 0, Some(0)))
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

    bob.move_to_channel(90).await;
    carol.move_to_channel(90).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(7, vec![voice_target_user(bob.session_id)]))
        .await;
    alice
        .send_voice_tcp(7, 31, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(&bob, &alice, "Bob should receive direct voice target audio").await;
    expect_no_voice(
        &carol,
        "Carol should not receive audio targeted only at Bob's session",
    )
    .await;
}

/// Checks channel voice targets without child or link expansion.
/// Expected: users in the target channel receive shout audio; users in child
/// channels do not.
#[tokio::test]
async fn voice_target_to_channel_shouts_only_to_that_channel() {
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
        .create_channel(Channel::new(100, "TargetChannel".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(101, "TargetChild".to_owned(), 0, 0, Some(100)))
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

    bob.move_to_channel(100).await;
    carol.move_to_channel(101).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(100, false, false, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 32, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(&bob, &alice, "Bob should receive channel shout audio").await;
    expect_no_voice(
        &carol,
        "Carol in a child channel should not receive a non-recursive channel target",
    )
    .await;
}

/// Checks that cached channel voice target recipients are invalidated when
/// client channel membership changes.
#[tokio::test]
async fn voice_target_channel_cache_tracks_client_moves() {
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
        .create_channel(Channel::new(102, "CachedTarget".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(
            103,
            "CachedElsewhere".to_owned(),
            0,
            0,
            Some(0),
        ))
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

    bob.move_to_channel(102).await;
    carol.move_to_channel(103).await;
    expect_user_channel(&bob, 102, "Bob enters cached target channel").await;
    expect_user_channel(&carol, 103, "Carol enters elsewhere channel").await;
    bob.drain_now().await;
    carol.drain_now().await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(102, false, false, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 42, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob should receive the first cached channel target packet",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol should not receive the first cached channel target packet",
    )
    .await;

    bob.move_to_channel(103).await;
    carol.move_to_channel(102).await;
    expect_user_channel(&bob, 103, "Bob leaves cached target channel").await;
    expect_user_channel(&carol, 102, "Carol enters cached target channel").await;
    bob.drain_now().await;
    carol.drain_now().await;

    alice
        .send_voice_tcp(7, 43, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &carol,
        &alice,
        "Carol should receive the second cached channel target packet",
    )
    .await;
    expect_no_voice(
        &bob,
        "Bob should not receive the second cached channel target packet after moving away",
    )
    .await;
}

/// Checks that a plain channel voice target to the sender's current channel is
/// allowed by Speak permission and does not require Whisper.
#[tokio::test]
async fn voice_target_plain_current_channel_uses_speak_permission() {
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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
    chans
        .create_channel(Channel::new(105, "CurrentTarget".to_owned(), 0, 0, Some(0)))
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

    admin
        .set_acls(
            105,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: true,
                inherited: false,
                user_id: None,
                group: Some("all".into()),
                grant: 0,
                deny: ACLPermissions::Whisper as u32,
            }],
            true,
        )
        .await;

    alice.move_to_channel(105).await;
    bob.move_to_channel(105).await;
    alice
        .recv_until(
            |m| {
                matches!(m, Message::UserState(us)
                    if us.session == Some(alice.session_id) && us.channel_id == Some(105))
            },
            VOICE_DEADLINE,
        )
        .await
        .expect("Alice enters current target channel");
    bob.recv_until(
        |m| {
            matches!(m, Message::UserState(us)
                if us.session == Some(bob.session_id) && us.channel_id == Some(105))
        },
        VOICE_DEADLINE,
    )
    .await
    .expect("Bob enters current target channel");
    bob.drain_now().await;

    let alice_server = server
        .server
        .get_clients()
        .get_client(alice.server_session)
        .await
        .expect("Alice is still connected");
    let perms =
        crate::client::acl::compute_permissions_for_client(&server.server, &alice_server, 105)
            .await;
    assert!(perms.contains(ACLPermissions::Speak));
    assert!(!perms.contains(ACLPermissions::Whisper));

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(105, false, false, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 36, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob should hear a plain current-channel VoiceTarget when Alice can Speak");
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
    assert_eq!(
        audio.format,
        PacketFormat::Protobuf,
        "1.5 recipient should expose the outbound voice context"
    );
    assert_eq!(
        audio.target,
        AudioTarget::VoiceTarget(1),
        "plain current-channel VoiceTarget should still process as target shout routing"
    );
}

/// Checks that the plain-current-channel Speak exception does not leak into
/// recursive child-channel targets.
#[tokio::test]
async fn voice_target_to_current_channel_children_still_requires_whisper() {
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
    chans
        .create_channel(Channel::new(106, "CurrentParent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(
            107,
            "CurrentChild".to_owned(),
            0,
            0,
            Some(106),
        ))
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

    admin
        .set_acls(
            106,
            vec![ChanAcl {
                apply_here: true,
                apply_subs: true,
                inherited: false,
                user_id: None,
                group: Some("all".into()),
                grant: 0,
                deny: ACLPermissions::Whisper as u32,
            }],
            true,
        )
        .await;

    alice.move_to_channel(106).await;
    bob.move_to_channel(107).await;
    expect_user_channel(&alice, 106, "Alice enters current parent channel").await;
    expect_user_channel(&bob, 107, "Bob enters current child channel").await;
    bob.drain_now().await;

    let alice_server = server
        .server
        .get_clients()
        .get_client(alice.server_session)
        .await
        .expect("Alice is still connected");
    let parent_perms =
        crate::client::acl::compute_permissions_for_client(&server.server, &alice_server, 106)
            .await;
    let child_perms =
        crate::client::acl::compute_permissions_for_client(&server.server, &alice_server, 107)
            .await;
    assert!(parent_perms.contains(ACLPermissions::Speak));
    assert!(!parent_perms.contains(ACLPermissions::Whisper));
    assert!(!child_perms.contains(ACLPermissions::Whisper));

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(106, true, false, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 38, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_no_voice(
        &bob,
        "Bob should not hear recursive current-channel VoiceTarget without Whisper",
    )
    .await;
}

/// Checks child-channel expansion for channel voice targets.
/// Expected: users in descendant channels receive shout audio when
/// `children` is enabled.
#[tokio::test]
async fn voice_target_to_children_shouts_to_descendants() {
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
        .create_channel(Channel::new(110, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(111, "Child".to_owned(), 0, 0, Some(110)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(112, "Elsewhere".to_owned(), 0, 0, Some(0)))
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

    bob.move_to_channel(111).await;
    carol.move_to_channel(112).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(110, true, false, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 33, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob in a child channel should receive recursive channel target audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol in an unrelated channel should not receive recursive channel target audio",
    )
    .await;
}

/// Checks linked-channel expansion for channel voice targets.
/// Expected: users in linked channels receive shout audio when `links` is
/// enabled.
#[tokio::test]
async fn voice_target_to_linked_channels_shouts_across_links() {
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
        .create_channel(Channel::new(120, "LinkSource".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(121, "Linked".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(122, "Unlinked".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans.add_link(120, 121).await.unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(121).await;
    carol.move_to_channel(122).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(120, false, true, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 34, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob in a linked channel should receive linked voice target audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol in an unlinked channel should not receive linked voice target audio",
    )
    .await;
}

/// Checks that the plain-current-channel Speak exception does not leak into
/// linked-channel targets.
#[tokio::test]
async fn voice_target_to_current_channel_links_still_requires_whisper() {
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
    chans
        .create_channel(Channel::new(
            123,
            "CurrentLinkSource".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(124, "CurrentLinked".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans.add_link(123, 124).await.unwrap();

    let admin = TestClient::connect_and_authenticate(&server, "admin", None)
        .await
        .expect("admin");
    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    for channel_id in [123, 124] {
        admin
            .set_acls(
                channel_id,
                vec![ChanAcl {
                    apply_here: true,
                    apply_subs: true,
                    inherited: false,
                    user_id: None,
                    group: Some("all".into()),
                    grant: 0,
                    deny: ACLPermissions::Whisper as u32,
                }],
                true,
            )
            .await;
    }

    alice.move_to_channel(123).await;
    bob.move_to_channel(124).await;
    expect_user_channel(&alice, 123, "Alice enters current linked source channel").await;
    expect_user_channel(&bob, 124, "Bob enters linked channel").await;
    bob.drain_now().await;

    let alice_server = server
        .server
        .get_clients()
        .get_client(alice.server_session)
        .await
        .expect("Alice is still connected");
    let source_perms =
        crate::client::acl::compute_permissions_for_client(&server.server, &alice_server, 123)
            .await;
    let linked_perms =
        crate::client::acl::compute_permissions_for_client(&server.server, &alice_server, 124)
            .await;
    assert!(source_perms.contains(ACLPermissions::Speak));
    assert!(!source_perms.contains(ACLPermissions::Whisper));
    assert!(!linked_perms.contains(ACLPermissions::Whisper));

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(123, false, true, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 39, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_no_voice(
        &bob,
        "Bob should not hear linked current-channel VoiceTarget without Whisper",
    )
    .await;
}

/// Checks group filtering for channel voice targets.
/// Expected: only recipients whose authenticated groups match the target's
/// `group` field receive shout audio.
#[tokio::test]
async fn voice_target_to_specific_group_filters_recipients() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["casters".into()]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(130, "Grouped".to_owned(), 0, 0, Some(0)))
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

    bob.move_to_channel(130).await;
    carol.move_to_channel(130).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(130, false, false, Some("casters"))],
        ))
        .await;
    alice
        .send_voice_tcp(7, 35, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob should receive group-filtered voice target audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol should not receive voice target audio for a group she is not in",
    )
    .await;
}

/// Checks group filtering for channel listeners.
/// Expected: a listener subscribed to the target channel is still excluded
/// when the channel VoiceTarget has a simple group they do not belong to.
#[tokio::test]
async fn voice_target_group_filter_excludes_non_member_listeners() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["casters".into()]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(
            131,
            "GroupedListener".to_owned(),
            0,
            0,
            Some(0),
        ))
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

    bob.move_to_channel(131).await;
    listen_to_channel(
        &carol,
        131,
        "Carol starts listening to the grouped target channel",
    )
    .await;
    expect_user_channel(&bob, 131, "Bob enters grouped target channel").await;
    bob.drain_now().await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(131, false, false, Some("casters"))],
        ))
        .await;
    alice
        .send_voice_tcp(7, 37, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob should receive group-filtered voice target audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol should not receive listener audio for a group she is not in",
    )
    .await;
}

/// Checks group filtering for listeners reached via child-channel expansion.
#[tokio::test]
async fn voice_target_group_filter_applies_to_child_channel_listeners() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["casters".into()]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(132, "GroupedParent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(
            133,
            "GroupedChild".to_owned(),
            0,
            0,
            Some(132),
        ))
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

    listen_to_channel(
        &bob,
        133,
        "Bob starts listening to the grouped child channel",
    )
    .await;
    listen_to_channel(
        &carol,
        133,
        "Carol starts listening to the grouped child channel",
    )
    .await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(132, true, false, Some("casters"))],
        ))
        .await;
    alice
        .send_voice_tcp(7, 40, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob should receive group-filtered child listener audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol should not receive child listener audio for a group she is not in",
    )
    .await;
}

/// Checks group filtering for listeners reached via linked-channel expansion.
#[tokio::test]
async fn voice_target_group_filter_applies_to_linked_channel_listeners() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["casters".into()]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(
            134,
            "GroupedLinkSource".to_owned(),
            0,
            0,
            Some(0),
        ))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(135, "GroupedLinked".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans.add_link(134, 135).await.unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    listen_to_channel(
        &bob,
        135,
        "Bob starts listening to the grouped linked channel",
    )
    .await;
    listen_to_channel(
        &carol,
        135,
        "Carol starts listening to the grouped linked channel",
    )
    .await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(134, false, true, Some("casters"))],
        ))
        .await;
    alice
        .send_voice_tcp(7, 41, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob should receive group-filtered linked listener audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol should not receive linked listener audio for a group she is not in",
    )
    .await;
}

/// Stresses shout routing against an anonymized production-sized channel tree.
/// 500 clients per selected top-level branch are deterministically scattered
/// across the real topology, then a superuser shouts to channel targets with
/// exact, recursive, linked, recursive+linked, and group-filtered settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voice_target_large_root_multi_branch_1000_clients_shout_matrix() {
    let server = spawn_test_server(TestServerOpts {
        max_users: (LARGE_TREE_CLIENTS + 8) as u64,
        client_idle_timeout_secs: LARGE_TREE_AUTHENTICATE_TIMEOUT_MS / 1_000,
        auth_finalization_concurrency: LARGE_TREE_AUTH_FINALIZATION_CONCURRENCY,
        authenticate_timeout_ms: LARGE_TREE_AUTHENTICATE_TIMEOUT_MS,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    for idx in 0..LARGE_TREE_CLIENTS {
        let username = format!("load-client-{idx:03}");
        let user_id = 10_000 + idx as u32;
        let groups = if idx % 5 == 0 {
            vec!["casters".into()]
        } else {
            Vec::new()
        };
        server
            .authenticator
            .register_user(&username, None, Some(user_id), groups);
    }

    let specs = large_tree_channel_specs();
    let tree = large_tree_channel_tree(&specs);
    let link_groups = large_tree_link_groups(&specs);
    let server_roots = large_tree_server_roots(&specs, &tree, LARGE_TREE_SERVER_BRANCHES);
    let cases = large_tree_shout_cases(&tree, &link_groups, &server_roots);
    let branch_leaf_channels = server_roots
        .iter()
        .map(|root| large_tree_leaves_under(&tree, *root))
        .collect::<Vec<_>>();

    let chans = server.server.get_channels();
    let mut created = HashSet::from([0u32]);
    let mut pending: Vec<&LargeTreeChannelSpec> = specs
        .iter()
        .filter(|spec| spec.parent_id.is_some())
        .collect();
    while !pending.is_empty() {
        let before = pending.len();
        let mut remaining = Vec::new();
        for spec in pending {
            let parent_id = spec.parent_id.expect("non-root channel");
            if !created.contains(&parent_id) {
                remaining.push(spec);
                continue;
            }
            chans
                .create_channel(Channel::new(
                    spec.id,
                    spec.name.clone(),
                    spec.position,
                    spec.max_users,
                    Some(parent_id),
                ))
                .await
                .unwrap();
            created.insert(spec.id);
        }
        assert!(
            remaining.len() < before,
            "large channel tree fixture contains parent cycles or missing parents"
        );
        pending = remaining;
    }
    for spec in &specs {
        for &linked_id in &spec.links {
            if spec.id < linked_id {
                chans.add_link(spec.id, linked_id).await.unwrap();
            }
        }
    }

    let mut rng = SmallRng::seed_from_u64(LARGE_TREE_SEED);
    let mut placements = Vec::with_capacity(LARGE_TREE_CLIENTS);
    for idx in 0..LARGE_TREE_CLIENTS {
        let branch_index = idx / LARGE_TREE_CLIENTS_PER_BRANCH;
        let branch_local_index = idx % LARGE_TREE_CLIENTS_PER_BRANCH;
        let branch_leaves = &branch_leaf_channels[branch_index];
        let random_channel = branch_leaves[rng.random_range(0..branch_leaves.len())];
        let channel_id = if branch_index == 0 {
            match branch_local_index {
                0..=19 => cases[0].target_channel,
                20..=39 => deepest_descendant_or_self(&tree, cases[1].target_channel),
                40..=59 => cases[2].target_channel,
                60..=79 => deepest_descendant_or_self(&tree, cases[3].target_channel),
                80..=99 => *large_tree_target_channels(&tree, &link_groups, &cases[2])
                    .iter()
                    .find(|&&id| id != cases[2].target_channel)
                    .unwrap_or(&cases[2].target_channel),
                100..=119 => *large_tree_target_channels(&tree, &link_groups, &cases[3])
                    .iter()
                    .find(|&&id| id != cases[3].target_channel)
                    .unwrap_or(&cases[3].target_channel),
                _ => random_channel,
            }
        } else {
            random_channel
        };
        placements.push(channel_id);
        server
            .server
            .get_user_channel_cache()
            .remember_last_channel(&(10_000 + idx as u32).to_string(), channel_id)
            .await
            .unwrap();
    }

    let mut clients = Vec::with_capacity(LARGE_TREE_CLIENTS);
    for branch_index in 0..LARGE_TREE_SERVER_BRANCHES {
        let branch_start = branch_index * LARGE_TREE_CLIENTS_PER_BRANCH;
        let branch_end = branch_start + LARGE_TREE_CLIENTS_PER_BRANCH;
        let server_ref = &server;
        let branch_wall = Instant::now();
        eprintln!(
            "large_tree_connect branch={} clients={} start",
            branch_index, LARGE_TREE_CLIENTS_PER_BRANCH
        );
        let mut pending = FuturesUnordered::new();
        for idx in branch_start..branch_end {
            let username = format!("load-client-{idx:03}");
            pending.push(async move {
                let connected_at = Instant::now();
                let result = connect_large_tree_load_client(server_ref, &username).await;
                (idx, connected_at.elapsed(), result)
            });
        }

        let mut connected = Vec::with_capacity(LARGE_TREE_CLIENTS_PER_BRANCH);
        let mut progress_tick = tokio::time::interval(Duration::from_secs(5));
        progress_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        while connected.len() < LARGE_TREE_CLIENTS_PER_BRANCH {
            tokio::select! {
                item = pending.next() => {
                    let Some((idx, elapsed, client)) = item else {
                        break;
                    };
                    let client =
                        client.unwrap_or_else(|err| panic!("connect large-tree client {idx}: {err:?}"));
                    connected.push((idx, client));
                    if connected.len() % 50 == 0 || connected.len() == LARGE_TREE_CLIENTS_PER_BRANCH {
                        eprintln!(
                            "large_tree_connect branch={} completed={} pending={} last_client={} last_ms={} elapsed_ms={}",
                            branch_index,
                            connected.len(),
                            pending.len(),
                            idx,
                            elapsed.as_millis(),
                            branch_wall.elapsed().as_millis(),
                        );
                    }
                }
                _ = progress_tick.tick() => {
                    let local_clients = server.server.get_clients().get_local_clients().await;
                    let authenticated = local_clients.iter().filter(|client| client.is_authenticated()).count();
                    let published = local_clients.iter().filter(|client| client.is_published()).count();
                    let auth_calls = server.authenticator.authenticated_auxiliary_data().len();
                    eprintln!(
                        "large_tree_connect branch={} waiting completed={} pending={} local={} authenticated={} published={} auth_calls={} elapsed_ms={}",
                        branch_index,
                        connected.len(),
                        pending.len(),
                        local_clients.len(),
                        authenticated,
                        published,
                        auth_calls,
                        branch_wall.elapsed().as_millis(),
                    );
                }
            }
        }
        assert_eq!(
            connected.len(),
            LARGE_TREE_CLIENTS_PER_BRANCH,
            "large-tree branch {branch_index} should authenticate every client"
        );
        connected.sort_by_key(|(idx, _)| *idx);

        for (idx, client) in connected {
            clients.push(LargeTreeClient {
                client,
                channel_id: placements[idx],
                in_casters: idx % 5 == 0,
            });
        }
    }

    wait_for_large_tree_clients_indexed(&server, &clients).await;
    let alice = TestClient::connect_and_authenticate_with_deadline(
        &server,
        "alice",
        None,
        LARGE_TREE_CONNECT_DEADLINE,
    )
    .await
    .expect("alice");
    drain_large_tree_clients_until_quiet(&alice, &clients).await;

    for case in cases {
        let expected = large_tree_expected_recipients(&clients, &tree, &link_groups, &case);
        assert!(
            !expected.is_empty(),
            "{} should have at least one recipient",
            case.label
        );

        drain_large_tree_clients_until_quiet(&alice, &clients).await;
        alice
            .set_voice_target(voice_target(
                case.slot,
                vec![voice_target_channel(
                    case.target_channel,
                    case.children,
                    case.links,
                    case.group,
                )],
            ))
            .await;
        wait_for_voice_target_installed(&server, &alice, case.slot).await;
        sync_large_tree_test_client_stream(&alice, 0x571E_8000 + case.slot as u64, case.label)
            .await;
        drain_large_tree_clients_until_quiet(&alice, &clients).await;
        let frames = large_tree_voice_segment(&case);
        assert!(
            large_tree_segment_send_span(&frames) >= LARGE_TREE_MIN_SPEAK_SPAN,
            "{} should continuously speak for at least {:?}",
            case.label,
            LARGE_TREE_MIN_SPEAK_SPAN
        );
        send_and_assert_large_tree_shout_delivery(&alice, &clients, &expected, &case, &frames)
            .await;
    }
}

// ── Real UDP / OCB2 tests ──────────────────────────────────────────────────

async fn open_udp_pair(alice: &mut TestClient, bob: &mut TestClient) {
    alice.open_udp().await.expect("alice udp bind");
    bob.open_udp().await.expect("bob udp bind");
    // Each client sends an encrypted ping; the server's IP-fallback decrypt
    // succeeds and binds the client's UDP address as a side effect.
    alice.udp_handshake().await.expect("alice udp handshake");
    bob.udp_handshake().await.expect("bob udp handshake");
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn voice_udp_ping_echoes_encrypted_timestamp() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

    let mut alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    alice.open_udp().await.expect("alice udp bind");
    alice.udp_handshake().await.expect("alice udp ping");

    let ping = alice
        .recv_udp_ping(VOICE_DEADLINE)
        .await
        .expect("encrypted udp ping response");
    assert_eq!(ping.timestamp, 1);
    assert_eq!(ping.format, PacketFormat::Legacy);
}

/// Checks real UDP voice routing, encryption, and decryption for one channel.
/// Expected: Bob decrypts Alice's byte-identical Opus payload and sender
/// session. This follows Mumble's UDP decrypt/route/encrypt path in
/// `D:\mumble\src\murmur\Server.cpp::run` and `processMsg`, and shitspeak's
/// OCB2 UDP path in `D:\shitspeak\client.go` plus `D:\shitspeak\cryptstate`.
#[tokio::test]
async fn voice_udp_same_channel_round_trips_and_decrypts() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let mut alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let mut bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    open_udp_pair(&mut alice, &mut bob).await;

    alice
        .send_voice_udp(0, 100, Bytes::from_static(SAMPLE_OPUS))
        .await
        .expect("alice send_voice_udp");

    let audio = bob
        .recv_voice_udp(VOICE_DEADLINE)
        .await
        .expect("Bob should receive Alice's voice over real UDP");
    assert_eq!(
        opus_frame(&audio.audio_payload),
        SAMPLE_OPUS,
        "opus payload should round-trip byte-identical through OCB2 + routing"
    );
    assert_eq!(audio.sender_session, Some(alice.server_session));
}

/// Checks TCP-tunneled voice using the Mumble 1.5 protobuf audio format.
/// Expected: a 1.5 recipient receives protobuf-format audio with the same Opus
/// frame and sender session. The wire format comes from
/// `D:\mumble\src\MumbleUDP.proto` and Mumble protocol handling; shitspeak
/// keeps the same generated protocol surface in `D:\shitspeak\mumbleproto`.
#[tokio::test]
async fn voice_tcp_protobuf_round_trips() {
    // Two 1.5+ clients exchange voice in the official protobuf wire format
    // over the TCP tunnel: Alice sends `[0x00, MumbleUDP.Audio]`; the server
    // routes; Bob receives the same payload re-encoded in protobuf because
    // his declared version is also 1.5.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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

    alice
        .send_voice_tcp_protobuf(0, 11, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.5) should receive Alice's protobuf voice over TCP tunnel");
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
    assert_eq!(
        audio.format,
        PacketFormat::Protobuf,
        "1.5 recipient must receive protobuf-format voice"
    );
}

/// Checks UDP voice using the Mumble 1.5 protobuf audio format.
/// Expected: the full encrypt/decrypt routing path preserves the Opus payload
/// and returns protobuf-format audio to a 1.5 recipient. This is sourced from
/// `D:\mumble\src\MumbleUDP.proto`, `D:\mumble\src\murmur\Server.cpp::run`,
/// and shitspeak's UDP crypt/protocol path in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_udp_protobuf_round_trips_and_decrypts() {
    // Same as above but over real UDP/OCB2 — exercises the full protobuf
    // pipeline: client encrypt → server decrypt → protobuf decode →
    // re-encode protobuf for recipient → encrypt → client decrypt.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let mut alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let mut bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    open_udp_pair(&mut alice, &mut bob).await;

    alice
        .send_voice_udp_protobuf(0, 12, Bytes::from_static(SAMPLE_OPUS))
        .await
        .expect("alice send_voice_udp_protobuf");

    let audio = bob
        .recv_voice_udp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.5) should receive Alice's protobuf voice over UDP");
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
    assert_eq!(
        audio.format,
        PacketFormat::Protobuf,
        "1.5 recipient must receive protobuf-format voice"
    );
}

/// Checks per-recipient voice encoding based on declared protocol version.
/// Expected: Bob declaring 1.5 receives protobuf voice, while Charlie declaring
/// 1.4 receives legacy voice from the same send. Mumble sets protocol-version
/// aware UDP encoders in `D:\mumble\src\murmur\Server.cpp`; shitspeak's generated
/// `D:\shitspeak\mumbleproto` and client version handling provide the parity source.
#[tokio::test]
async fn voice_udp_format_matches_recipient_proto_version() {
    // One sender, two recipients with different declared protocol versions.
    // The server must encode each outbound voice packet in the format the
    // recipient declared via its `Version` message: protobuf for 1.5+,
    // legacy Opus for 1.4 and below.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
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
        .register_user("charlie", None, Some(3), vec![]);

    // Alice sends as 1.5 (protobuf cleartext on the wire).
    let mut alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 5, 0))
            .await
            .expect("alice");
    // Bob declares 1.5 → expects protobuf back.
    let mut bob =
        TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 5, 0))
            .await
            .expect("bob");
    // Charlie declares 1.4 → expects legacy back.
    let mut charlie =
        TestClient::connect_with_version(&server, "charlie", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("charlie");

    alice.open_udp().await.expect("alice udp bind");
    bob.open_udp().await.expect("bob udp bind");
    charlie.open_udp().await.expect("charlie udp bind");
    alice.udp_handshake().await.expect("alice handshake");
    bob.udp_handshake().await.expect("bob handshake");
    charlie.udp_handshake().await.expect("charlie handshake");
    tokio::time::sleep(Duration::from_millis(300)).await;

    alice
        .send_voice_udp_protobuf(0, 21, Bytes::from_static(SAMPLE_OPUS))
        .await
        .expect("alice send protobuf");

    let bob_audio = bob
        .recv_voice_udp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.5) should receive Alice's voice");
    assert_eq!(opus_frame(&bob_audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(bob_audio.sender_session, Some(alice.server_session));
    assert_eq!(
        bob_audio.format,
        PacketFormat::Protobuf,
        "Bob declared 1.5 — server must send protobuf format"
    );

    let charlie_audio = charlie
        .recv_voice_udp(VOICE_DEADLINE)
        .await
        .expect("Charlie (1.4) should receive Alice's voice");
    assert_eq!(opus_frame(&charlie_audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(charlie_audio.sender_session, Some(alice.server_session));
    assert_eq!(
        charlie_audio.format,
        PacketFormat::Legacy,
        "Charlie declared 1.4 — server must send legacy format"
    );
}

/// Checks that the server protocol version gates protobuf voice output before
/// recipient capability is considered.
#[tokio::test]
async fn voice_server_protocol_version_gates_protobuf_voice() {
    async fn run_case(
        server_protocol_version: ProtocolVersion,
        bob_version: ProtocolVersion,
        charlie_version: ProtocolVersion,
        expected_bob: PacketFormat,
        expected_charlie: PacketFormat,
    ) {
        let server = spawn_test_server(TestServerOpts {
            server_protocol_version,
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
            .register_user("charlie", None, Some(3), vec![]);

        let alice =
            TestClient::connect_with_version(&server, "alice", None, PROTOBUF_INTRODUCED_VERSION)
                .await
                .expect("alice");
        let bob = TestClient::connect_with_version(&server, "bob", None, bob_version)
            .await
            .expect("bob");
        let charlie = TestClient::connect_with_version(&server, "charlie", None, charlie_version)
            .await
            .expect("charlie");

        alice
            .send_voice_tcp_protobuf(0, 22, Bytes::from_static(SAMPLE_OPUS))
            .await;

        let bob_audio = bob
            .recv_voice_tcp(VOICE_DEADLINE)
            .await
            .expect("Bob should receive Alice's voice over TCP tunnel");
        assert_eq!(opus_frame(&bob_audio.audio_payload), SAMPLE_OPUS);
        assert_eq!(bob_audio.sender_session, Some(alice.server_session));
        assert_eq!(bob_audio.format, expected_bob);

        let charlie_audio = charlie
            .recv_voice_tcp(VOICE_DEADLINE)
            .await
            .expect("Charlie should receive Alice's voice over TCP tunnel");
        assert_eq!(opus_frame(&charlie_audio.audio_payload), SAMPLE_OPUS);
        assert_eq!(charlie_audio.sender_session, Some(alice.server_session));
        assert_eq!(charlie_audio.format, expected_charlie);
    }

    run_case(
        ProtocolVersion::new(1, 4, 0),
        PROTOBUF_INTRODUCED_VERSION,
        PROTOBUF_INTRODUCED_VERSION,
        PacketFormat::Legacy,
        PacketFormat::Legacy,
    )
    .await;
    run_case(
        PROTOBUF_INTRODUCED_VERSION,
        PROTOBUF_INTRODUCED_VERSION,
        ProtocolVersion::new(1, 4, 0),
        PacketFormat::Protobuf,
        PacketFormat::Legacy,
    )
    .await;
}

/// Checks legacy UDP voice when both clients declare pre-1.5 protocol support.
/// Expected: Bob receives legacy-format Opus with Alice's sender session. This
/// is the Mumble 1.4-compatible path in `D:\mumble\src\murmur\Server.cpp::run`
/// and `processMsg`, mirrored by shitspeak's legacy packet handling in
/// `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_udp_legacy_to_legacy_round_trips() {
    // Both clients declare 1.4 → both speak legacy. Reproduces the path the
    // real Mumble 1.4.x client uses: legacy in, legacy out.
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let mut alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("alice");
    let mut bob =
        TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("bob");

    open_udp_pair(&mut alice, &mut bob).await;

    alice
        .send_voice_udp(0, 100, Bytes::from_static(SAMPLE_OPUS))
        .await
        .expect("alice send_voice_udp legacy");

    let audio = bob
        .recv_voice_udp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.4) should receive Alice's legacy voice over UDP");
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
    assert_eq!(audio.format, PacketFormat::Legacy);
}

/// Checks that UDP voice obeys the same channel isolation as TCP voice.
/// Expected: Bob in a different channel receives no UDP audio from Alice. The
/// behavior comes from Mumble's receiver selection in
/// `D:\mumble\src\murmur\Server.cpp::processMsg` and shitspeak's regular voice
/// routing in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_udp_different_channel_does_not_route() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(60, "Lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let mut alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let mut bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(60).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    open_udp_pair(&mut alice, &mut bob).await;

    alice
        .send_voice_udp(0, 200, Bytes::from_static(SAMPLE_OPUS))
        .await
        .expect("alice send_voice_udp");

    let received = bob.recv_voice_udp(NEGATIVE_WINDOW).await;
    assert!(
        received.is_none(),
        "Bob in a different channel should NOT receive Alice's voice over UDP"
    );
}

// ── Legacy-specific packet behaviors (pre-protobuf / 1.4 clients) ───────────

/// Checks that the legacy Opus terminator bit survives TCP routing.
/// Expected: Bob receives an Opus payload with `is_terminator = true` and the
/// same frame bytes. The bit is defined by Mumble's legacy UDP/TCP audio format
/// in `D:\mumble\src\MumbleProtocol.*`; shitspeak preserves it in the legacy
/// packet path in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_tcp_legacy_terminator_bit_preserved() {
    // Opus terminator bit (0x2000 in the legacy size_flag) must survive the
    // server routing pipeline. Doc: "The 14th bit (mask: 0x2000) is the
    // terminator bit which signals whether the packet is the last one in the
    // voice transmission."
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("alice");
    let bob = TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
        .await
        .expect("bob");

    alice
        .send_voice_tcp_terminator(0, 50, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.4) should receive Alice's terminator frame");
    let AudioPayload::Opus(p) = &audio.audio_payload else {
        panic!("expected Opus payload, got {:?}", audio.audio_payload);
    };
    assert!(
        p.is_terminator,
        "terminator bit must survive the server routing pipeline"
    );
    assert_eq!(p.frame.as_ref(), SAMPLE_OPUS);
}

/// Checks that the protobuf Opus terminator flag survives TCP routing.
/// Expected: Bob receives a protobuf-decoded Opus payload with the terminator
/// flag intact. This follows `D:\mumble\src\MumbleUDP.proto`'s audio fields and
/// Mumble routing in `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak
/// uses the same generated Mumble UDP protobuf definitions.
#[tokio::test]
async fn voice_tcp_protobuf_terminator_bit_preserved() {
    // Same invariant as above but through the 1.5+ protobuf pipeline.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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

    alice
        .send_voice_tcp_protobuf_terminator(0, 51, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.5) should receive Alice's terminator frame");
    let AudioPayload::Opus(p) = &audio.audio_payload else {
        panic!("expected Opus payload, got {:?}", audio.audio_payload);
    };
    assert!(
        p.is_terminator,
        "terminator bit must survive the server routing pipeline (protobuf)"
    );
    assert_eq!(p.frame.as_ref(), SAMPLE_OPUS);
}

/// Checks that legacy positional audio data survives TCP routing.
/// Expected: Bob receives the same XYZ coordinates and Opus payload Alice sent.
/// Mumble defines positional audio in the legacy audio packet format and routes
/// it through `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak preserves
/// positional bytes in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_tcp_legacy_positional_data_round_trip() {
    // Positional audio (optional 3 × f32 XYZ appended after the Opus payload
    // in the legacy wire format) must survive server routing unchanged.
    // Doc: "The XYZ coordinates of the audio source."
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("alice");
    let bob = TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
        .await
        .expect("bob");

    let positional = [1.5_f32, 2.5, 3.5];
    alice
        .send_voice_tcp_with_positional(0, 60, Bytes::from_static(SAMPLE_OPUS), positional)
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.4) should receive Alice's voice with positional data");
    assert_eq!(
        audio.positional_data,
        Some(positional),
        "positional XYZ must survive legacy routing unchanged"
    );
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
}

/// Checks that protobuf positional audio data survives TCP routing.
/// Expected: Bob receives the same XYZ coordinates and Opus payload from the
/// `MumbleUDP.Audio` protobuf field. The source is `D:\mumble\src\MumbleUDP.proto`
/// and Murmur's voice routing; shitspeak keeps the same protobuf schema under
/// `D:\shitspeak\mumbleproto`.
#[tokio::test]
async fn voice_tcp_protobuf_positional_data_round_trip() {
    // Same as above but through the 1.5+ protobuf pipeline, where positional
    // data is encoded in the MumbleUDP.Audio proto field.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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

    let positional = [4.0_f32, 5.0, 6.0];
    alice
        .send_voice_tcp_protobuf_with_positional(0, 61, Bytes::from_static(SAMPLE_OPUS), positional)
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.5) should receive Alice's voice with positional data");
    assert_eq!(
        audio.positional_data,
        Some(positional),
        "positional XYZ must survive protobuf routing unchanged"
    );
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
}

/// Checks legacy server loopback target handling.
/// Expected: target 31 echoes the packet only to Alice and not to Bob. Mumble
/// handles `ReservedTargetIDs::SERVER_LOOPBACK` in
/// `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak mirrors target 31
/// handling in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_tcp_legacy_server_loopback() {
    // target=31 (Server Loopback) must echo the packet back to the sender;
    // other channel members must not receive it. Doc: "Server Loopback (31)".
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("alice");
    let bob = TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
        .await
        .expect("bob");

    alice
        .send_voice_tcp(31, 70, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let echo = alice
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Alice should receive her own loopback packet (legacy)");
    assert_eq!(
        opus_frame(&echo.audio_payload),
        SAMPLE_OPUS,
        "loopback must echo the original audio payload"
    );

    let received_by_bob = bob.recv_voice_tcp(NEGATIVE_WINDOW).await;
    assert!(
        received_by_bob.is_none(),
        "Bob must not receive the server loopback packet"
    );
}

/// Checks protobuf server loopback target handling.
/// Expected: target 31 echoes protobuf voice only to Alice and does not route it
/// to Bob. This comes from Mumble's reserved server-loopback target in
/// `D:\mumble\src\murmur\Server.cpp::processMsg` and shitspeak's equivalent
/// target handling in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_tcp_protobuf_server_loopback() {
    // Same as above but through the 1.5+ protobuf pipeline.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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

    alice
        .send_voice_tcp_protobuf(31, 71, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let echo = alice
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Alice should receive her own loopback packet (protobuf)");
    assert_eq!(
        opus_frame(&echo.audio_payload),
        SAMPLE_OPUS,
        "loopback must echo the original audio payload"
    );

    let received_by_bob = bob.recv_voice_tcp(NEGATIVE_WINDOW).await;
    assert!(
        received_by_bob.is_none(),
        "Bob must not receive the server loopback packet"
    );
}
