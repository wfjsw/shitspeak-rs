use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;

use shitspeak_core::{ClientSessionIdentifier, default_server_id};

use crate::application::ApplicationLayer;
use crate::application::config::ApplicationConfig;
use crate::application::moderation::runtime::testing::RecordingApplier;
use crate::application::proto::{
    self, ModerationCommand, UserStatePatch, VoiceFrame, VoiceIntent, VoiceIntentKind,
    VoiceIntentNormal,
};
use crate::application::voice::{AudioSink, sink::testing::RecordingSink};
use crate::overlay::{OverlayInboundMessage, RoutingMetric, SeedPeer};
use crate::status;
use crate::testing::{
    Cluster, FaultSelector, MessageType, full_mesh_seeds, line_seeds, wait_for_full_alive_mesh,
    wait_for_full_routing, wait_until, wait_until_with,
};
use shitspeak_s2s_transport::{MessageClass, PeerAddress, ServiceLevel, TransportKind};

const LONG_HAUL_ONE_WAY_LATENCY: Duration = Duration::from_millis(104);
const LONG_HAUL_JITTER: Duration = Duration::from_millis(4);
const LONG_HAUL_FRAME_COUNT: usize = 48;
const LONG_HAUL_REPAIR_FRAME_OFFSET: usize = 4;
const LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET: Duration = Duration::from_millis(400);
const SHOUT_FRAME_INTERVAL: Duration = Duration::from_millis(20);
const SHOUT_FRAME_LATENCY_BUDGET: Duration = Duration::from_secs(3);
const SHOUT_STREAM_GAP_BUDGET: Duration = Duration::from_millis(250);
const LOW_RTT_GAP_OBSERVE_BUDGET: Duration = Duration::from_millis(300);
const LOW_RTT_REPAIR_RELEASE_BUDGET: Duration = Duration::from_millis(40);
const LOW_RTT_SUFFIX_BURST_BUDGET: Duration = Duration::from_millis(20);

fn normal_voice_intent(channel_id: u32) -> VoiceIntent {
    VoiceIntent {
        kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
            source_channel: channel_id,
        })),
    }
}

struct TimedVoiceDelivery {
    frame: VoiceFrame,
    is_repair: bool,
    delivered_at: Instant,
}

struct TimedVoiceSink {
    tx: tokio::sync::mpsc::UnboundedSender<TimedVoiceDelivery>,
}

#[async_trait]
impl AudioSink for TimedVoiceSink {
    async fn deliver(
        &self,
        _from_immediate: shitspeak_core::NodeIdentifier,
        frame: VoiceFrame,
        is_repair: bool,
    ) {
        let _ = self.tx.send(TimedVoiceDelivery {
            frame,
            is_repair,
            delivered_at: Instant::now(),
        });
    }
}

fn repair_frame(
    sender_session: u32,
    sender_epoch: u64,
    s2s_seq: u64,
    payload: Bytes,
) -> VoiceFrame {
    VoiceFrame {
        sender_session,
        server_id: default_server_id(),
        sender_epoch,
        s2s_seq,
        target_kind: 0,
        is_terminator: false,
        payload,
        intent: Some(normal_voice_intent(0)),
        proactive_copy: false,
    }
}

async fn receive_timed_voice_stream(
    sink_rx: &mut tokio::sync::mpsc::UnboundedReceiver<TimedVoiceDelivery>,
    sender_session: u32,
    expected: &[(Bytes, bool)],
    deadline: Duration,
) -> Vec<TimedVoiceDelivery> {
    tokio::time::timeout(deadline, async {
        let mut deliveries = Vec::with_capacity(expected.len());
        while deliveries.len() < expected.len() {
            let delivery = sink_rx
                .recv()
                .await
                .expect("timed voice sink should remain installed");
            if delivery.frame.sender_session != sender_session {
                continue;
            }
            let expected_index = deliveries.len();
            let (expected_payload, expected_terminator) = &expected[expected_index];
            if delivery.frame.payload != *expected_payload {
                if expected
                    .iter()
                    .any(|(payload, _)| delivery.frame.payload == *payload)
                {
                    panic!(
                        "timed voice sink delivered measured frame {expected_index} out of order"
                    );
                }
                continue;
            }
            assert_eq!(delivery.frame.is_terminator, *expected_terminator);
            deliveries.push(delivery);
        }
        deliveries
    })
    .await
    .expect("timed voice sink did not receive the measured stream in time")
}

fn prometheus_total(node: &crate::testing::Node, metric: &str, labels: &[(&str, &str)]) -> f64 {
    status::prometheus_samples(&node.overlay, &node.transport, None)
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

#[derive(Default, serde::Deserialize)]
struct VoiceTreeIoSnapshot {
    #[serde(default)]
    source: u16,
    #[serde(default)]
    destination: u16,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    sent_count: u64,
}

fn tree_original_sent_count(source: u16, destination: u16) -> u64 {
    crate::debug_io::snapshot()
        .into_iter()
        .filter_map(|row| {
            serde_json::to_value(row)
                .ok()
                .and_then(|value| serde_json::from_value::<VoiceTreeIoSnapshot>(value).ok())
        })
        .filter(|row| {
            row.kind == "application.voice.tree.original"
                && row.source == source
                && row.destination == destination
        })
        .map(|row| row.sent_count)
        .sum()
}

async fn wait_for_tree_voice_forwarding(
    app: &ApplicationLayer,
    source_node: u16,
    destination_node: u16,
) {
    const MAX_ACTIVATION_PROBES: u64 = 30;

    let mut previous_originals = tree_original_sent_count(source_node, destination_node);
    for attempt in 0..MAX_ACTIVATION_PROBES {
        app.voice()
            .send_for_channel(
                ClientSessionIdentifier::new(source_node, 900_000 + attempt as u32)
                    .expect("valid tree warmup session")
                    .to_u32(),
                default_server_id(),
                0,
                true,
                Bytes::from(format!("tree-warmup-{attempt}").into_bytes()),
            )
            .await
            .expect("send tree warmup frame");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let originals = tree_original_sent_count(source_node, destination_node);
        if originals > previous_originals {
            return;
        }
        previous_originals = originals;
    }

    panic!(
        "tree delivery did not forward a frame from node {source_node} to node {destination_node}"
    );
}

/// Helper: bidirectional 2-node seeding.
fn seed_pair(idx: usize, ids: &[u16], ports: &[u16]) -> Vec<SeedPeer> {
    let other = if idx == 0 { 1 } else { 0 };
    vec![SeedPeer::new(
        ids[other],
        vec![PeerAddress::new(
            crate::testing::loopback(ports[other]),
            TransportKind::Tcp,
        )],
    )]
}

/// Checks S2S application voice passthrough ordering.
/// Expected: B's installed `AudioSink` receives 100 frames from A in sequence,
/// with byte-identical payloads and terminator metadata. Voice semantics come
/// from Mumble's `D:\mumble\src\murmur\Server.cpp::processMsg` and shitspeak's
/// `D:\shitspeak\client.go`; this crate's S2S application layer preserves
/// those frames over the overlay.
#[tokio::test]
async fn two_node_voice_passthrough_in_order() {
    let cluster = Cluster::build(&[1, 2], seed_pair).await;
    let a = cluster.node(1);
    let b = cluster.node(2);

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "2-node mesh failed to converge"
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(8)).await,
        "2-node routing failed to converge"
    );

    let app_a = ApplicationLayer::new(a.overlay.clone(), ApplicationConfig::default());
    let app_b = ApplicationLayer::new(b.overlay.clone(), ApplicationConfig::default());
    let sink_b = RecordingSink::new();
    app_b.voice().set_audio_sink(sink_b.clone());

    const N_FRAMES: u64 = 100;
    let sender_session = 0xABC_12345_u32;
    for i in 0..N_FRAMES {
        let payload = Bytes::from(format!("opus-frame-{i}").into_bytes());
        let is_terminator = i + 1 == N_FRAMES;
        app_a
            .voice()
            .send_broadcast(
                sender_session,
                default_server_id(),
                0,
                is_terminator,
                payload,
                normal_voice_intent(0),
            )
            .await
            .expect("send_broadcast");
        if !is_terminator {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    let ok = wait_until(Duration::from_secs(8), || sink_b.len() as u64 == N_FRAMES).await;
    let received = sink_b.snapshot();
    assert!(
        ok,
        "B received only {}/{} voice frames",
        received.len(),
        N_FRAMES
    );

    for (i, (from, frame)) in received.iter().enumerate() {
        assert_eq!(*from, 1, "frame {i} from-immediate should be node A (1)");
        assert_eq!(frame.sender_session, sender_session);
        assert_eq!(
            frame.s2s_seq, i as u64,
            "frame {i} has wrong s2s_seq {}",
            frame.s2s_seq
        );
        assert_eq!(frame.target_kind, 0);
        assert_eq!(frame.is_terminator, i as u64 + 1 == N_FRAMES);
        let expected = format!("opus-frame-{i}").into_bytes();
        assert_eq!(frame.payload, expected, "frame {i} payload mismatch");
    }

    app_a.shutdown().await;
    app_b.shutdown().await;
    cluster.shutdown_all().await;
}

/// Checks that a line-seeded cluster may learn a direct A-C transport path.
/// Expected: A eventually routes voice directly to C, so only C receives the
/// unicast frame.
#[tokio::test]
async fn three_node_voice_unicast_learns_direct_connection() {
    let cluster = Cluster::build(&[1, 2, 3], line_seeds).await;
    let a = cluster.node(1);
    let b = cluster.node(2);
    let c = cluster.node(3);

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "3-node line mesh failed to converge"
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(8)).await,
        "3-node line routing failed to converge"
    );
    assert!(
        wait_until(Duration::from_secs(8), || {
            a.overlay.route_to_with_metric(
                3,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            ) == Some(3)
        })
        .await,
        "A should learn a direct voice route to C; reliable={:?}, voice={:?}",
        a.overlay.route_to(3, ServiceLevel::Reliable),
        a.overlay.route_to_with_metric(
            3,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
        )
    );

    let app_a = ApplicationLayer::new(a.overlay.clone(), ApplicationConfig::default());
    let app_b = ApplicationLayer::new(b.overlay.clone(), ApplicationConfig::default());
    let app_c = ApplicationLayer::new(c.overlay.clone(), ApplicationConfig::default());
    let sink_b = RecordingSink::new();
    let sink_c = RecordingSink::new();
    app_b.voice().set_audio_sink(sink_b.clone());
    app_c.voice().set_audio_sink(sink_c.clone());

    app_a
        .voice()
        .send_unicast(
            0xABC_12345,
            default_server_id(),
            0,
            false,
            Bytes::from_static(b"line-frame"),
            normal_voice_intent(0),
            3,
        )
        .await
        .expect("send_unicast");

    let ok = wait_until(Duration::from_secs(8), || sink_c.len() == 1).await;
    assert!(
        ok,
        "expected C destination sink to receive one frame; got B={}, C={}",
        sink_b.len(),
        sink_c.len()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        sink_b.len(),
        0,
        "B should not receive a frame when A routes directly to C"
    );

    let c_received = sink_c.snapshot();
    let (from, frame) = &c_received[0];
    assert_eq!(*from, 1, "C should see original voice sender A");
    assert_eq!(frame.sender_session, 0xABC_12345);
    assert_eq!(frame.target_kind, 0);
    assert_eq!(frame.payload, b"line-frame".as_ref());

    app_a.shutdown().await;
    app_b.shutdown().await;
    app_c.shutdown().await;
    cluster.shutdown_all().await;
}

/// Checks targeted voice over a forced routed line topology.
/// Expected: B forwards A's frame to C without rendering it locally because
/// B is not listed as an overlay destination and transit processing is off.
#[tokio::test]
async fn three_node_voice_unicast_forwards_without_transit_delivery_when_direct_blocked() {
    let cluster = Cluster::build(&[1, 2, 3], line_seeds).await;
    let a = cluster.node(1);
    let b = cluster.node(2);
    let c = cluster.node(3);

    // Keep A and C from forming a usable direct overlay neighbor edge. They
    // can still learn each other's LSAs through B and route through B.
    a.chaos.block(3);
    c.chaos.block(1);

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "3-node line mesh failed to converge"
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(8)).await,
        "3-node line routing failed to converge"
    );
    assert!(
        wait_until(Duration::from_secs(8), || {
            a.overlay.route_to_with_metric(
                3,
                ServiceLevel::BestEffort,
                RoutingMetric::ConversationalQuality,
            ) == Some(2)
        })
        .await,
        "A should route voice to C through B when A-C is blocked; reliable={:?}, voice={:?}",
        a.overlay.route_to(3, ServiceLevel::Reliable),
        a.overlay.route_to_with_metric(
            3,
            ServiceLevel::BestEffort,
            RoutingMetric::ConversationalQuality,
        )
    );

    let app_a = ApplicationLayer::new(a.overlay.clone(), ApplicationConfig::default());
    let app_b = ApplicationLayer::new(b.overlay.clone(), ApplicationConfig::default());
    let app_c = ApplicationLayer::new(c.overlay.clone(), ApplicationConfig::default());
    let sink_b = RecordingSink::new();
    let sink_c = RecordingSink::new();
    app_b.voice().set_audio_sink(sink_b.clone());
    app_c.voice().set_audio_sink(sink_c.clone());

    app_a
        .voice()
        .send_unicast(
            0xABC_12345,
            default_server_id(),
            0,
            false,
            Bytes::from_static(b"line-frame"),
            normal_voice_intent(0),
            3,
        )
        .await
        .expect("send_unicast");

    let ok = wait_until(Duration::from_secs(8), || sink_c.len() == 1).await;
    assert!(
        ok,
        "expected C destination sink to receive one frame through B; got B={}, C={}",
        sink_b.len(),
        sink_c.len()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        sink_b.len(),
        0,
        "B should forward the unicast frame without rendering it locally"
    );

    let c_received = sink_c.snapshot();
    let (from, frame) = &c_received[0];
    assert_eq!(*from, 1, "C should see original voice sender A");
    assert_eq!(frame.sender_session, 0xABC_12345);
    assert_eq!(frame.target_kind, 0);
    assert_eq!(frame.payload, b"line-frame".as_ref());

    app_a.shutdown().await;
    app_b.shutdown().await;
    app_c.shutdown().await;
    cluster.shutdown_all().await;
}

/// Checks S2S application moderation delivery to the owning node only.
/// Expected: B receives exactly one moderation envelope for its owned target,
/// while A and C receive none. The user-state moderation semantics come from
/// `D:\mumble\src\murmur\Messages.cpp::msgUserState` and
/// `D:\shitspeak\message.go::handleUserStateMessage`; this crate adds the S2S
/// owner-directed envelope.
#[tokio::test]
async fn three_node_moderation_unicasts_to_owner() {
    let cluster = Cluster::build(&[1, 2, 3], full_mesh_seeds).await;
    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "3-node mesh failed to converge"
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(8)).await,
        "3-node routing failed to converge"
    );

    let app_a = ApplicationLayer::new(
        cluster.node(1).overlay.clone(),
        ApplicationConfig::default(),
    );
    let app_b = ApplicationLayer::new(
        cluster.node(2).overlay.clone(),
        ApplicationConfig::default(),
    );
    let app_c = ApplicationLayer::new(
        cluster.node(3).overlay.clone(),
        ApplicationConfig::default(),
    );

    let applier_a = RecordingApplier::new();
    let applier_b = RecordingApplier::new();
    let applier_c = RecordingApplier::new();
    app_a.moderation().set_applier(applier_a.clone());
    app_b.moderation().set_applier(applier_b.clone());
    app_c.moderation().set_applier(applier_c.clone());

    let actor = ClientSessionIdentifier::new(1, 0x12345).unwrap();
    let target = ClientSessionIdentifier::new(2, 0x67890).unwrap();
    let patch = UserStatePatch {
        channel_id: None,
        mute: Some(true),
        deaf: None,
        suppress: None,
        priority_speaker: None,
        listening_channel_add: vec![],
        listening_channel_remove: vec![],
        expected_from_channel: Some(0),
    };
    app_a
        .moderation()
        .dispatch_user_state(None, actor, target, patch.clone())
        .await
        .expect("dispatch_user_state");

    // B should receive exactly one envelope; A and C should receive
    // none. Wait up to 5 s for delivery to converge.
    let ok = wait_until(Duration::from_secs(5), || applier_b.len() == 1).await;
    assert!(
        ok,
        "B never received the moderation envelope (got {})",
        applier_b.len()
    );
    let received = applier_b.snapshot();
    let (from, env) = &received[0];
    assert_eq!(*from, 1, "envelope arrived at B from A");
    assert_eq!(env.actor_session, actor.to_u32());
    assert_eq!(env.target_session, target.to_u32());
    match &env.command {
        Some(ModerationCommand::UserState(p)) => assert_eq!(*p, patch),
        other => panic!("expected UserState, got {other:?}"),
    }

    // Briefly wait — non-routing of duplicate to A or C might race the
    // single hop, so allow a short settle.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        applier_a.len(),
        0,
        "A should not have received its own envelope"
    );
    assert_eq!(
        applier_c.len(),
        0,
        "C should not have received the envelope"
    );

    app_a.shutdown().await;
    app_b.shutdown().await;
    app_c.shutdown().await;
    cluster.shutdown_all().await;
}

/// Checks S2S voice behavior when the destination has no audio sink installed.
/// Expected: A's sends succeed and B decodes then drops frames without panics.
/// Mumble/shitspeak define the voice frame semantics; this crate's S2S
/// application layer defines the missing-sink drop behavior.
#[tokio::test]
async fn two_node_voice_drops_when_sink_missing() {
    let cluster = Cluster::build(&[1, 2], seed_pair).await;
    let a = cluster.node(1);
    let b = cluster.node(2);

    assert!(wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await);
    assert!(wait_for_full_routing(&cluster, Duration::from_secs(8)).await);

    let app_a = ApplicationLayer::new(a.overlay.clone(), ApplicationConfig::default());
    let app_b = ApplicationLayer::new(b.overlay.clone(), ApplicationConfig::default());
    // Note: no sink installed on B.

    for i in 0..10u64 {
        app_a
            .voice()
            .send_broadcast(
                0xABC,
                default_server_id(),
                0,
                false,
                Bytes::from(format!("frame-{i}").into_bytes()),
                normal_voice_intent(0),
            )
            .await
            .expect("send_broadcast");
    }
    // Give the dispatch task time to drain — should be a no-op.
    tokio::time::sleep(Duration::from_millis(200)).await;

    app_a.shutdown().await;
    app_b.shutdown().await;
    cluster.shutdown_all().await;
}

/// Exercises a marked repair over the long-haul distribution-tree path. The
/// receiver must emit the repaired gap and its following suffix immediately,
/// without adding application-level media pacing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2s_tree_voice_long_haul_repair_is_delivered_without_server_pacing() {
    let cluster = Cluster::build(&[8, 1], seed_pair).await;
    let node_8 = cluster.node(8);
    let node_1 = cluster.node(1);

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "long-haul pair failed to converge"
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(8)).await,
        "long-haul pair failed to learn routes"
    );

    // Shape only tree data. Delaying the complete control plane after the
    // transport is established makes the lightweight cluster harness tear
    // down its TCP peer before the voice assertion can start; the scenario
    // is specifically about data-plane long-haul reorder and repair.
    node_1.chaos.set_delay(
        FaultSelector::new(8, TransportKind::Tcp, MessageType::DistributionData),
        LONG_HAUL_ONE_WAY_LATENCY,
        LONG_HAUL_JITTER,
    );
    assert!(
        wait_until(Duration::from_secs(8), || node_8
            .transport_is_up(1, TransportKind::Tcp))
        .await,
        "long-haul source transport did not remain ready"
    );

    let app_8 = ApplicationLayer::new(node_8.overlay.clone(), ApplicationConfig::default());
    let app_1 = ApplicationLayer::new(node_1.overlay.clone(), ApplicationConfig::default());
    wait_for_tree_voice_forwarding(app_8.as_ref(), 8, 1).await;

    let (sink_tx, mut sink_rx) = tokio::sync::mpsc::unbounded_channel();
    app_1
        .voice()
        .set_audio_sink(Arc::new(TimedVoiceSink { tx: sink_tx }));

    let sender_session = ClientSessionIdentifier::new(8, 80_002)
        .expect("valid long-haul speaker session")
        .to_u32();
    let frames = (0..LONG_HAUL_FRAME_COUNT)
        .map(|offset| Bytes::from(format!("long-haul-repair-frame-{offset}").into_bytes()))
        .collect::<Vec<_>>();
    let expected = frames
        .iter()
        .enumerate()
        .map(|(offset, payload)| (payload.clone(), offset + 1 == frames.len()))
        .collect::<Vec<_>>();
    let source_voice = app_8.voice().clone();
    let repair_handler = app_1.voice().inbound_handler();
    let sender_epoch = node_8.overlay.local_boot_epoch();
    let repair_payload = frames[LONG_HAUL_REPAIR_FRAME_OFFSET].clone();
    let (repair_tx, repair_rx) = tokio::sync::oneshot::channel::<u64>();
    let repair_task = tokio::spawn(async move {
        let missing_s2s_seq = repair_rx.await.expect("missing sequence signal");
        // Let the following tree original open the receiver-side gap before
        // supplying the same frame through the marked repair ingress path.
        // Stay inside the shaped path's 104 +/- 4 ms route-delay hint plus
        // the reorder deadline. At 140 ms this races the deadline and can
        // flush the suffix before the injected repair arrives.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let body = proto::encode_voice(&repair_frame(
            sender_session,
            sender_epoch,
            missing_s2s_seq,
            repair_payload,
        ))
        .expect("encode injected repair frame");
        repair_handler.handle(
            OverlayInboundMessage::new(
                8,
                ServiceLevel::BestEffort,
                MessageClass::HighPriority,
                body,
            )
            .with_distribution_repair(true),
        );
    });

    let tree_original_before = tree_original_sent_count(8, 1);
    let send_task = async {
        let mut sent_at = Vec::with_capacity(frames.len());
        let mut missing_s2s_seq = None;
        let mut repair_tx = Some(repair_tx);
        for (offset, payload) in frames.iter().enumerate() {
            sent_at.push(Instant::now());
            if offset == LONG_HAUL_REPAIR_FRAME_OFFSET {
                missing_s2s_seq = Some(source_voice.next_seq(sender_session));
            } else {
                source_voice
                    .send_for_channel(
                        sender_session,
                        default_server_id(),
                        0,
                        offset + 1 == frames.len(),
                        payload.clone(),
                    )
                    .await
                    .expect("send long-haul tree voice frame");
                if offset == LONG_HAUL_REPAIR_FRAME_OFFSET + 1 {
                    repair_tx
                        .take()
                        .expect("single repair signal")
                        .send(missing_s2s_seq.expect("reserved repair sequence"))
                        .expect("repair task should await signal");
                }
            }
            if offset + 1 != frames.len() {
                tokio::time::sleep(SHOUT_FRAME_INTERVAL).await;
            }
        }
        (Instant::now(), sent_at)
    };
    let ((send_end, sent_at), deliveries) = tokio::join!(
        send_task,
        receive_timed_voice_stream(
            &mut sink_rx,
            sender_session,
            &expected,
            SHOUT_FRAME_LATENCY_BUDGET,
        )
    );
    repair_task.await.expect("repair task should not panic");

    let tree_original_delta = tree_original_sent_count(8, 1).saturating_sub(tree_original_before);
    let max_latency = deliveries
        .iter()
        .zip(&sent_at)
        .map(|(delivery, sent_at)| delivery.delivered_at.saturating_duration_since(*sent_at))
        .max()
        .unwrap_or_default();
    let tail_latency = deliveries
        .last()
        .expect("measured stream should have a final frame")
        .delivered_at
        .saturating_duration_since(send_end);
    let max_frame_gap = deliveries
        .windows(2)
        .map(|window| {
            window[1]
                .delivered_at
                .saturating_duration_since(window[0].delivered_at)
        })
        .max()
        .unwrap_or_default();

    assert!(
        tree_original_delta >= (frames.len() - 1) as u64,
        "the measured original frames did not use the active tree"
    );
    assert!(
        deliveries[LONG_HAUL_REPAIR_FRAME_OFFSET].is_repair,
        "the injected frame was not marked as a repair"
    );
    assert!(
        max_latency <= LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET,
        "repaired long-haul voice was held for {max_latency:?}, expected <= {LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET:?}"
    );
    assert!(
        tail_latency <= LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET,
        "repaired long-haul voice tail was held for {tail_latency:?}, expected <= {LONG_HAUL_IMMEDIATE_DELIVERY_BUDGET:?}"
    );
    assert!(
        max_frame_gap <= SHOUT_STREAM_GAP_BUDGET,
        "repaired long-haul stream had a gap of {max_frame_gap:?}, expected <= {SHOUT_STREAM_GAP_BUDGET:?}"
    );

    app_8.shutdown().await;
    app_1.shutdown().await;
    cluster.shutdown_all().await;
}

/// A healthy nearby tree path must release a complete buffered suffix as soon
/// as a marked S2S repair fills its sole missing sequence, not on a media
/// timeline derived from the arbitrary application payloads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2s_tree_voice_low_rtt_node_8_to_node_3_releases_gap_suffix_without_media_pacing() {
    let cluster = Cluster::build(&[8, 3], seed_pair).await;
    let node_8 = cluster.node(8);
    let node_3 = cluster.node(3);

    assert!(
        wait_for_full_alive_mesh(&cluster, Duration::from_secs(8)).await,
        "low-RTT pair failed to converge"
    );
    assert!(
        wait_for_full_routing(&cluster, Duration::from_secs(8)).await,
        "low-RTT pair failed to learn routes"
    );

    let mut source_config = ApplicationConfig::default();
    source_config.voice.repair_max_extra_copies_per_frame = 0;
    let mut destination_config = source_config.clone();
    destination_config.voice.reorder_max_delay_ms = 500;
    destination_config.voice.adaptive_jitter_min_delay_ms = 500;
    destination_config.voice.adaptive_jitter_max_delay_ms = 500;

    let app_8 = ApplicationLayer::new(node_8.overlay.clone(), source_config);
    let app_3 = ApplicationLayer::new(node_3.overlay.clone(), destination_config);
    wait_for_tree_voice_forwarding(app_8.as_ref(), 8, 3).await;

    let (sink_tx, mut sink_rx) = tokio::sync::mpsc::unbounded_channel();
    app_3
        .voice()
        .set_audio_sink(Arc::new(TimedVoiceSink { tx: sink_tx }));

    let sender_session = ClientSessionIdentifier::new(8, 80_003)
        .expect("valid low-RTT speaker session")
        .to_u32();
    let frames = vec![
        Bytes::from_static(b"nearby-frame-a"),
        Bytes::from_static(b"nearby-frame-b"),
        Bytes::from_static(b"nearby-frame-c"),
        Bytes::from_static(b"nearby-frame-d"),
        Bytes::from_static(b"nearby-frame-e"),
    ];
    let expected = frames
        .iter()
        .enumerate()
        .map(|(offset, payload)| (payload.clone(), offset + 1 == frames.len()))
        .collect::<Vec<_>>();
    let source_voice = app_8.voice().clone();
    let repair_handler = app_3.voice().inbound_handler();
    let sender_epoch = node_8.overlay.local_boot_epoch();
    let receive_labels = [
        ("source", "3"),
        ("origin_node", "8"),
        ("from_immediate", "8"),
    ];
    let gap_buffered_before = prometheus_total(
        node_3,
        "shitspeak_s2s_voice_receive_events_total",
        &[
            receive_labels[0],
            receive_labels[1],
            receive_labels[2],
            ("result", "gap_buffered"),
        ],
    );
    let gap_filled_before = prometheus_total(
        node_3,
        "shitspeak_s2s_voice_receive_events_total",
        &[
            receive_labels[0],
            receive_labels[1],
            receive_labels[2],
            ("result", "gap_filled"),
        ],
    );

    let send_task = async {
        let first_sent_at = Instant::now();
        source_voice
            .send_for_channel(
                sender_session,
                default_server_id(),
                0,
                false,
                frames[0].clone(),
            )
            .await
            .expect("send low-RTT first voice frame");

        // Reserve sequence one, then let the remaining tree originals open a
        // real receiver-side gap. Payload contents are deliberately unrelated
        // to a media clock.
        let missing_s2s_seq = source_voice.next_seq(sender_session);
        for (offset, payload) in frames.iter().enumerate().skip(2) {
            source_voice
                .send_for_channel(
                    sender_session,
                    default_server_id(),
                    0,
                    offset + 1 == frames.len(),
                    payload.clone(),
                )
                .await
                .expect("send low-RTT later voice frame");
        }

        let expected_buffered_suffix = frames.len() - 2;
        assert!(
            wait_until_with(LOW_RTT_GAP_OBSERVE_BUDGET, Duration::from_millis(1), || {
                let measured_gap_buffered = prometheus_total(
                    node_3,
                    "shitspeak_s2s_voice_receive_events_total",
                    &[
                        receive_labels[0],
                        receive_labels[1],
                        receive_labels[2],
                        ("result", "gap_buffered"),
                    ],
                ) - gap_buffered_before;
                let pending = prometheus_total(
                    node_3,
                    "shitspeak_s2s_voice_reorder_pending",
                    &[("source", "3")],
                );
                measured_gap_buffered >= expected_buffered_suffix as f64
                    && pending >= expected_buffered_suffix as f64
            },)
            .await,
            "node 3 did not buffer the complete measured suffix before the reorder deadline"
        );

        let repair_injected_at = Instant::now();
        let body = proto::encode_voice(&repair_frame(
            sender_session,
            sender_epoch,
            missing_s2s_seq,
            frames[1].clone(),
        ))
        .expect("encode low-RTT injected repair frame");
        repair_handler.handle(
            OverlayInboundMessage::new(
                8,
                ServiceLevel::BestEffort,
                MessageClass::HighPriority,
                body,
            )
            .with_distribution_repair(true),
        );
        (first_sent_at, repair_injected_at)
    };
    let ((first_sent_at, repair_injected_at), deliveries) = tokio::join!(
        send_task,
        receive_timed_voice_stream(
            &mut sink_rx,
            sender_session,
            &expected,
            SHOUT_FRAME_LATENCY_BUDGET,
        )
    );

    let gap_buffered_delta = prometheus_total(
        node_3,
        "shitspeak_s2s_voice_receive_events_total",
        &[
            receive_labels[0],
            receive_labels[1],
            receive_labels[2],
            ("result", "gap_buffered"),
        ],
    ) - gap_buffered_before;
    let gap_filled_delta = prometheus_total(
        node_3,
        "shitspeak_s2s_voice_receive_events_total",
        &[
            receive_labels[0],
            receive_labels[1],
            receive_labels[2],
            ("result", "gap_filled"),
        ],
    ) - gap_filled_before;
    let repair_release = deliveries[1]
        .delivered_at
        .saturating_duration_since(repair_injected_at);
    let suffix_burst = deliveries[1..]
        .windows(2)
        .map(|window| {
            window[1]
                .delivered_at
                .saturating_duration_since(window[0].delivered_at)
        })
        .max()
        .unwrap_or_default();
    let first_release = deliveries[0]
        .delivered_at
        .saturating_duration_since(first_sent_at);

    assert!(
        gap_buffered_delta >= (frames.len() - 2) as f64,
        "node 3 did not buffer the complete suffix after the missing S2S sequence"
    );
    assert!(
        gap_filled_delta >= (frames.len() - 2) as f64,
        "the repair did not drain the complete buffered suffix"
    );
    assert!(
        deliveries[1].is_repair,
        "the injected frame was not marked as a repair"
    );
    assert!(
        repair_release <= LOW_RTT_REPAIR_RELEASE_BUDGET,
        "repair release was {repair_release:?}, expected <= {LOW_RTT_REPAIR_RELEASE_BUDGET:?}; a healthy remote stream must not use media pacing"
    );
    assert!(
        suffix_burst <= LOW_RTT_SUFFIX_BURST_BUDGET,
        "drained suffix had an artificial {suffix_burst:?} inter-packet gap, expected <= {LOW_RTT_SUFFIX_BURST_BUDGET:?}"
    );
    assert!(
        first_release <= SHOUT_FRAME_LATENCY_BUDGET,
        "first nearby frame was held for {first_release:?}"
    );

    app_8.shutdown().await;
    app_3.shutdown().await;
    cluster.shutdown_all().await;
}
