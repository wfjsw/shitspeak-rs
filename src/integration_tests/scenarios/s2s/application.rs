use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::client::client_session_identifier::ClientSessionIdentifier;
use crate::s2s::application::ApplicationLayer;
use crate::s2s::application::config::ApplicationConfig;
use crate::s2s::application::moderation::runtime::testing::RecordingApplier;
use crate::s2s::application::proto::{
    ModerationCommand, UserStatePatch, VoiceIntent, VoiceIntentKind, VoiceIntentNormal,
};
use crate::s2s::application::voice::sink::testing::RecordingSink;
use crate::s2s::overlay::{RoutingMetric, SeedPeer};
use crate::s2s::testing::{
    Cluster, full_mesh_seeds, line_seeds, wait_for_full_alive_mesh, wait_for_full_routing,
    wait_until,
};
use crate::s2s::transport::{PeerAddress, ServiceLevel, TransportKind};

fn normal_voice_intent(channel_id: u32) -> VoiceIntent {
    VoiceIntent {
        kind: Some(VoiceIntentKind::Normal(VoiceIntentNormal {
            source_channel: channel_id,
        })),
    }
}

/// Helper: bidirectional 2-node seeding.
fn seed_pair(idx: usize, _ids: &[u16], ports: &[u16]) -> Vec<SeedPeer> {
    let other = if idx == 0 { 1 } else { 0 };
    vec![SeedPeer::new(
        if other == 0 { 1 } else { 2 },
        vec![PeerAddress::new(
            crate::s2s::testing::loopback(ports[other]),
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
                crate::types::default_server_id(),
                0,
                is_terminator,
                payload,
                normal_voice_intent(0),
            )
            .await
            .expect("send_broadcast");
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
            crate::types::default_server_id(),
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
/// Expected: B receives A's frame while forwarding it to C, even though
/// B is not listed as an overlay destination.
#[tokio::test]
async fn three_node_voice_unicast_delivers_to_transit_node_when_direct_blocked() {
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
            crate::types::default_server_id(),
            0,
            false,
            Bytes::from_static(b"line-frame"),
            normal_voice_intent(0),
            3,
        )
        .await
        .expect("send_unicast");

    let ok = wait_until(Duration::from_secs(8), || {
        sink_b.len() == 1 && sink_c.len() == 1
    })
    .await;
    assert!(
        ok,
        "expected B transit and C destination sinks to receive one frame; got B={}, C={}",
        sink_b.len(),
        sink_c.len()
    );

    let b_received = sink_b.snapshot();
    let c_received = sink_c.snapshot();
    for (label, received) in [("B", &b_received), ("C", &c_received)] {
        let (from, frame) = &received[0];
        assert_eq!(*from, 1, "{label} should see original voice sender A");
        assert_eq!(frame.sender_session, 0xABC_12345);
        assert_eq!(frame.target_kind, 0);
        assert_eq!(frame.payload, b"line-frame".as_ref());
    }

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
                crate::types::default_server_id(),
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
