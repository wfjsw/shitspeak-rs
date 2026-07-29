//! End-to-end smoke tests for the unified `ConnectionManager`.
//!
//! Brings up two managers in the same process, has them dial each other and
//! exchange messages. The full mTLS-on-TCP path is exercised. Other
//! transports follow the same shape; only TCP is covered here so the test
//! surface stays compact.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::time::timeout;

use crate::testing::{
    Pki, install_provider_once, loopback, mint_pki, pick_free_port, pick_free_udp_port,
    s2s_network_test_guard,
};
use crate::{
    ConnectionManager, Inbound, LinkMetrics, MessageClass, PeerAddress, SeedAddress, SendOptions,
    ServiceLevel, TransportConfig, TransportKind,
};

fn config_for(pki: &Pki, node_idx: usize, tcp: SocketAddr) -> TransportConfig {
    let (cert, key) = &pki.nodes[node_idx];
    TransportConfig::new(pki.ca_path.clone(), cert.clone(), key.clone())
        .with_tcp_listen(tcp)
        .with_reconnect_check_interval(Duration::from_millis(50))
        .with_backoff_initial(Duration::from_millis(20))
        .with_backoff_cap(Duration::from_millis(200))
        .with_ping_interval(Duration::from_millis(200))
        .with_bandwidth_probe_interval(Duration::from_millis(200))
        .with_bandwidth_probe_size(1024)
}

fn config_with_tcp_and_udp(
    pki: &Pki,
    node_idx: usize,
    tcp: SocketAddr,
    udp: SocketAddr,
) -> TransportConfig {
    config_for(pki, node_idx, tcp)
        .with_udp_listen(udp)
        .with_udp_mtu(1400)
}

fn config_with_quic(pki: &Pki, node_idx: usize, quic: SocketAddr) -> TransportConfig {
    let (cert, key) = &pki.nodes[node_idx];
    TransportConfig::new(pki.ca_path.clone(), cert.clone(), key.clone())
        .with_quic_listen(quic)
        .with_reconnect_check_interval(Duration::from_millis(50))
        .with_backoff_initial(Duration::from_millis(20))
        .with_backoff_cap(Duration::from_millis(500))
        .with_ping_interval(Duration::from_millis(200))
        .with_quic_session_setup_timeout(Duration::from_secs(2))
}

#[tokio::test]
async fn quic_v2_maps_reliable_classes_and_best_effort_datagrams() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[41, 42]);
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    let cfg_a = config_with_quic(&pki, 0, loopback(port_a));
    let cfg_b = config_with_quic(&pki, 1, loopback(port_b));

    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();
    let (mgr_a, _inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    mgr_a
        .add_address(42, PeerAddress::new(loopback(port_b), TransportKind::Quic))
        .await;
    wait_for_link(&mgr_a, 42, TransportKind::Quic).await;
    wait_for_link(&mgr_b, 41, TransportKind::Quic).await;

    for (level, class, payload) in [
        (
            ServiceLevel::Reliable,
            MessageClass::Control,
            b"control".as_slice(),
        ),
        (
            ServiceLevel::ReliableLowLatency,
            MessageClass::HighPriority,
            b"high".as_slice(),
        ),
        (
            ServiceLevel::Reliable,
            MessageClass::Regular,
            b"regular".as_slice(),
        ),
        (
            ServiceLevel::BestEffort,
            MessageClass::HighPriority,
            b"voice-datagram".as_slice(),
        ),
        (
            ServiceLevel::BestEffort,
            MessageClass::Control,
            b"repair-datagram".as_slice(),
        ),
    ] {
        mgr_a
            .send(42, level, None, class, Bytes::copy_from_slice(payload))
            .await
            .unwrap();
        let received = match class {
            MessageClass::Control => inbound_b.control().recv(),
            MessageClass::HighPriority => inbound_b.high_priority().recv(),
            MessageClass::Regular => inbound_b.regular().recv(),
        };
        let received = timeout(Duration::from_secs(2), received)
            .await
            .expect("QUIC v2 receive timeout")
            .expect("inbound queue closed");
        assert_eq!(received.from(), 41);
        assert_eq!(received.transport(), TransportKind::Quic);
        assert_eq!(received.class(), class);
        assert_eq!(received.payload().as_ref(), payload);
        assert_eq!(received.level(), level);
    }

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

#[tokio::test]
async fn oversized_best_effort_uses_tcp_without_closing_quic_v2() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[47, 48]);
    let quic_port_a = pick_free_udp_port().await;
    let quic_port_b = pick_free_udp_port().await;
    let tcp_port_a = pick_free_port().await;
    let tcp_port_b = pick_free_port().await;
    let cfg_a =
        config_with_quic(&pki, 0, loopback(quic_port_a)).with_tcp_listen(loopback(tcp_port_a));
    let cfg_b =
        config_with_quic(&pki, 1, loopback(quic_port_b)).with_tcp_listen(loopback(tcp_port_b));

    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();
    let (mgr_a, _inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    mgr_a
        .add_address(
            48,
            PeerAddress::new(loopback(quic_port_b), TransportKind::Quic),
        )
        .await;
    mgr_a
        .add_address(
            48,
            PeerAddress::new(loopback(tcp_port_b), TransportKind::Tcp),
        )
        .await;
    wait_for_link(&mgr_a, 48, TransportKind::Quic).await;
    wait_for_link(&mgr_a, 48, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, 47, TransportKind::Quic).await;

    // This is larger than a QUIC DATAGRAM but well below the configured frame
    // limit. Strict s2s/2 streams must not carry BestEffort, so TCP is the
    // compatible reliable fallback while the QUIC session stays healthy.
    let payload = Bytes::from(vec![b'v'; 4 * 1024]);
    mgr_a
        .send(
            48,
            ServiceLevel::BestEffort,
            None,
            MessageClass::HighPriority,
            payload.clone(),
        )
        .await
        .unwrap();

    let received = timeout(Duration::from_secs(2), inbound_b.high_priority().recv())
        .await
        .expect("TCP fallback receive timeout")
        .expect("inbound queue closed");
    assert_eq!(received.from(), 47);
    assert_eq!(received.transport(), TransportKind::Tcp);
    // Legacy stream transports expose their physical service level on the
    // transport envelope. OverlayData inside the payload retains the
    // application's BestEffort contract.
    assert_eq!(received.level(), ServiceLevel::Reliable);
    assert_eq!(received.class(), MessageClass::HighPriority);
    assert_eq!(received.payload(), &payload);
    assert!(mgr_a.has_live_transport_kind(48, TransportKind::Quic));
    assert!(mgr_b.has_live_transport_kind(47, TransportKind::Quic));

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

#[tokio::test]
async fn quic_v1_fallback_keeps_best_effort_on_legacy_stream() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[43, 44]);
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    let cfg_a = config_with_quic(&pki, 0, loopback(port_a));
    let cfg_b = config_with_quic(&pki, 1, loopback(port_b)).with_quic_v1_only_for_test();

    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();
    let (mgr_a, _inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    mgr_a
        .add_address(44, PeerAddress::new(loopback(port_b), TransportKind::Quic))
        .await;
    wait_for_link(&mgr_a, 44, TransportKind::Quic).await;

    mgr_a
        .send(
            44,
            ServiceLevel::BestEffort,
            None,
            MessageClass::HighPriority,
            Bytes::from_static(b"legacy-best-effort"),
        )
        .await
        .unwrap();
    let received = timeout(Duration::from_secs(2), inbound_b.high_priority().recv())
        .await
        .expect("QUIC v1 receive timeout")
        .expect("inbound queue closed");
    assert_eq!(received.payload().as_ref(), b"legacy-best-effort");
    assert_eq!(received.transport(), TransportKind::Quic);

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

#[tokio::test]
async fn quic_v2_rejects_disabled_local_datagram_support() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[45, 46]);
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    let cfg_a = config_with_quic(&pki, 0, loopback(port_a))
        .with_quic_datagram_send_buffer_bytes(0)
        .with_quic_datagram_receive_buffer_bytes(0);
    let cfg_b = config_with_quic(&pki, 1, loopback(port_b));

    let (mgr_b, _inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();
    let (mgr_a, _inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    mgr_a
        .add_address(46, PeerAddress::new(loopback(port_b), TransportKind::Quic))
        .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!mgr_a.has_live_transport_kind(46, TransportKind::Quic));

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

fn config_for_compression(pki: &Pki, node_idx: usize, tcp: SocketAddr) -> TransportConfig {
    let (cert, key) = &pki.nodes[node_idx];
    TransportConfig::new(pki.ca_path.clone(), cert.clone(), key.clone())
        .with_tcp_listen(tcp)
        .with_reconnect_check_interval(Duration::from_millis(50))
        .with_backoff_initial(Duration::from_millis(20))
        .with_backoff_cap(Duration::from_millis(200))
        .with_ping_interval(Duration::from_secs(60))
        .with_idle_ping_interval(Duration::from_secs(60))
        .with_bandwidth_probe_interval(Duration::from_secs(60))
        .with_bandwidth_probe_size(0)
        .with_bandwidth_window(Duration::from_secs(30))
        .with_compression_min_bytes(1)
        .with_compression_min_savings_percent(0)
        .with_compression_level(1)
}

#[derive(Clone, Copy, Debug)]
enum CompressionScenario {
    Identity,
    Zstd,
    AdaptiveZstd,
}

impl CompressionScenario {
    fn apply(self, cfg: TransportConfig) -> TransportConfig {
        match self {
            Self::Identity => cfg.with_compression_enabled(false),
            Self::Zstd => cfg
                .with_compression_enabled(true)
                .with_compression_adaptive_dictionary_enabled(false),
            Self::AdaptiveZstd => cfg
                .with_compression_enabled(true)
                .with_compression_adaptive_dictionary_enabled(true),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct WireEfficiency {
    payload_bytes: u64,
    wire_bytes: u64,
}

impl WireEfficiency {
    fn wire_ratio(self) -> f64 {
        self.wire_bytes as f64 / self.payload_bytes.max(1) as f64
    }

    fn savings_vs(self, baseline: Self) -> f64 {
        if baseline.wire_bytes == 0 {
            return 0.0;
        }
        100.0 * (baseline.wire_bytes.saturating_sub(self.wire_bytes) as f64)
            / baseline.wire_bytes as f64
    }
}

/// Checks that a manager discovers a seed peer without knowing its node id in
/// advance.
/// Expected: the seed address is enough to establish mTLS, read the peer's
/// identity from its certificate, and register a live TCP link on both sides.
#[tokio::test]
async fn seed_address_discovers_peer_without_node_id() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[1, 2]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let cfg_a = config_for(&pki, 0, loopback(port_a)).with_seed_target(SeedAddress::new(
        loopback(port_b).to_string(),
        TransportKind::Tcp,
    ));
    let cfg_b = config_for(&pki, 1, loopback(port_b));

    // Start the listener before A performs its initial, unidentified seed
    // dial. `cfg_a` has only B's socket address, not B's node id.
    let (mgr_b, _inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();
    let (mgr_a, _inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();

    wait_for_link(&mgr_a, 2, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, 1, TransportKind::Tcp).await;

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

/// Checks that two S2S transport managers establish mTLS over TCP and exchange
/// both regular and high-priority frames.
/// Expected: each side receives the peer's payload with the correct node id,
/// message class, and TCP transport marker. Mumble does not define S2S
/// transport; this crate extends the side-channel idea present in
/// `D:\shitspeak\slavehub.go` while preserving Mumble's authenticated-server
/// assumptions from `D:\mumble\src\murmur`.
#[tokio::test]
async fn two_node_tcp_data_roundtrip() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[1, 2]);

    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let cfg_a = config_for(&pki, 0, loopback(port_a));
    let cfg_b = config_for(&pki, 1, loopback(port_b));

    let (mgr_a, mut inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();
    assert_eq!(mgr_a.local_node_id(), 1);
    assert_eq!(mgr_b.local_node_id(), 2);

    // A learns where to dial B.
    mgr_a
        .add_address(2, PeerAddress::new(loopback(port_b), TransportKind::Tcp))
        .await;

    // Wait for the supervisor on A to dial and complete the mTLS handshake.
    // Side B accepts and registers A automatically when the handshake lands.
    wait_for_link(&mgr_a, 2, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, 1, TransportKind::Tcp).await;

    // A → B
    mgr_a
        .send(
            2,
            ServiceLevel::Reliable,
            None,
            MessageClass::Regular,
            Bytes::from_static(b"hi-from-a"),
        )
        .await
        .unwrap();
    let recv = timeout(Duration::from_secs(2), inbound_b.regular().recv())
        .await
        .expect("a→b recv timeout")
        .expect("a→b recv channel closed");
    assert_eq!(recv.from(), 1);
    assert_eq!(recv.transport(), TransportKind::Tcp);
    assert_eq!(recv.class(), MessageClass::Regular);
    assert_eq!(recv.payload().as_ref(), b"hi-from-a");

    // B → A
    mgr_b
        .send(
            1,
            ServiceLevel::Reliable,
            None,
            MessageClass::HighPriority,
            Bytes::from_static(b"hi-from-b"),
        )
        .await
        .unwrap();
    let recv = timeout(Duration::from_secs(2), inbound_a.high_priority().recv())
        .await
        .expect("b→a recv timeout")
        .expect("b→a recv channel closed");
    assert_eq!(recv.from(), 2);
    assert_eq!(recv.class(), MessageClass::HighPriority);
    assert_eq!(recv.payload().as_ref(), b"hi-from-b");

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
    let _ = inbound_a; // keep alive until end
    let _ = inbound_b;
}

/// Checks that an idle link does not synthesize throughput from bandwidth probes.
/// Expected: liveness pings establish RTT samples, but passive throughput stays
/// zero until real Data frames flow.
#[tokio::test]
async fn idle_link_reports_zero_passive_throughput() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[100, 200]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let cfg_a = config_for(&pki, 0, loopback(port_a));
    let cfg_b = config_for(&pki, 1, loopback(port_b));

    let (mgr_a, _ina) = ConnectionManager::start(cfg_a).await.unwrap();
    let (_mgr_b, _inb) = ConnectionManager::start(cfg_b).await.unwrap();

    mgr_a
        .add_address(200, PeerAddress::new(loopback(port_b), TransportKind::Tcp))
        .await;
    wait_for_link(&mgr_a, 200, TransportKind::Tcp).await;

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        if let Some(per_t) = mgr_a.metrics_snapshot().for_node(200) {
            if let Some(tcp) = per_t.get(&TransportKind::Tcp) {
                if tcp.samples() >= 1 {
                    assert_eq!(tcp.observed_recv_bps(), 0.0);
                    assert_eq!(tcp.observed_sent_bps(), 0.0);
                    assert_eq!(tcp.estimated_throughput_bps(), 0.0);
                    assert_eq!(tcp.throughput_confidence_ppm(), 0);
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never recorded keepalive RTT samples");
}

/// Checks passive throughput directionality for one-way data.
/// Expected: sending A -> B raises only A's observed sent rate and B's
/// observed recv rate; the opposite directions remain idle.
#[tokio::test]
async fn one_way_tcp_data_updates_directional_passive_throughput() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[101, 202]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let cfg_a = config_for(&pki, 0, loopback(port_a));
    let cfg_b = config_for(&pki, 1, loopback(port_b));

    let (mgr_a, _inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();

    mgr_a
        .add_address(202, PeerAddress::new(loopback(port_b), TransportKind::Tcp))
        .await;
    wait_for_link(&mgr_a, 202, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, 101, TransportKind::Tcp).await;

    let payload = Bytes::from_static(b"one-way-passive-throughput");
    mgr_a
        .send(
            202,
            ServiceLevel::Reliable,
            None,
            MessageClass::Regular,
            payload.clone(),
        )
        .await
        .unwrap();

    let recv = timeout(Duration::from_secs(2), inbound_b.regular().recv())
        .await
        .expect("a->b recv timeout")
        .expect("a->b recv channel closed");
    assert_eq!(recv.from(), 101);
    assert_eq!(recv.transport(), TransportKind::Tcp);
    assert_eq!(recv.payload(), &payload);

    let (sender, receiver) = wait_for_one_way_tcp_passive_metrics(&mgr_a, 202, &mgr_b, 101).await;
    assert!(sender.observed_sent_bps() > 0.0);
    assert_eq!(sender.observed_recv_bps(), 0.0);
    assert_eq!(
        sender.estimated_throughput_bps(),
        sender.observed_sent_bps()
    );
    assert!(receiver.observed_recv_bps() > 0.0);
    assert_eq!(receiver.observed_sent_bps(), 0.0);

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

/// Checks adaptive L1 compression over a real mTLS TCP transport.
/// Expected: after a warmup phase, the learned dictionary keeps delivery
/// correct and reduces measured transport-frame bytes far below identity,
/// while staying competitive with ordinary zstd on the same payload shape.
#[tokio::test]
async fn adaptive_compression_reduces_tcp_wire_bytes_after_warmup() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();

    let identity =
        measure_tcp_wire_efficiency(151, 252, CompressionScenario::Identity, false).await;
    let zstd = measure_tcp_wire_efficiency(153, 254, CompressionScenario::Zstd, false).await;
    let adaptive =
        measure_tcp_wire_efficiency(155, 256, CompressionScenario::AdaptiveZstd, true).await;

    eprintln!(
        "adaptive compression efficiency: payload={}B identity_wire={}B zstd_wire={}B adaptive_wire={}B adaptive_ratio={:.3} savings_vs_identity={:.1}% savings_vs_zstd={:.1}%",
        adaptive.payload_bytes,
        identity.wire_bytes,
        zstd.wire_bytes,
        adaptive.wire_bytes,
        adaptive.wire_ratio(),
        adaptive.savings_vs(identity),
        adaptive.savings_vs(zstd),
    );

    assert_eq!(identity.payload_bytes, adaptive.payload_bytes);
    assert_eq!(zstd.payload_bytes, adaptive.payload_bytes);
    assert!(
        adaptive.wire_bytes * 100 <= identity.wire_bytes * 45,
        "adaptive compression should save at least 55% vs identity; identity={identity:?} adaptive={adaptive:?}"
    );
    assert!(
        adaptive.wire_bytes <= zstd.wire_bytes,
        "adaptive dictionary should not be larger than plain zstd for this repeated S2S payload shape; zstd={zstd:?} adaptive={adaptive:?}"
    );
}

/// Checks mixed capability safety for rolling upgrades or per-node opt-out.
/// Expected: an adaptive sender trains locally, but because the receiver does
/// not advertise dictionary support in transport Hello, the sender keeps using
/// identity/plain-zstd frames and delivery continues after warmup.
#[tokio::test]
async fn adaptive_compression_waits_for_peer_dictionary_capability() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[157, 258]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let cfg_a = config_for_compression(&pki, 0, loopback(port_a))
        .with_compression_adaptive_dictionary_enabled(true);
    let cfg_b = config_for_compression(&pki, 1, loopback(port_b))
        .with_compression_adaptive_dictionary_enabled(false);

    let (mgr_a, _inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();

    mgr_a
        .add_address(258, PeerAddress::new(loopback(port_b), TransportKind::Tcp))
        .await;
    wait_for_link(&mgr_a, 258, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, 157, TransportKind::Tcp).await;

    for i in 0..120 {
        send_tcp_compression_sample(&mgr_a, &mut inbound_b, 258, i).await;
    }

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

/// Checks service-level fallback when only TCP is available.
/// Expected: a BestEffort frame is still delivered over TCP, with the received
/// frame recording TCP as the actual transport. This is this crate's S2S
/// transport policy, built to carry Mumble/shitspeak server messages even when
/// an unreliable path is unavailable.
#[tokio::test]
async fn upward_fallback_uses_tcp_for_best_effort() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[10, 20]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let cfg_a = config_for(&pki, 0, loopback(port_a));
    let cfg_b = config_for(&pki, 1, loopback(port_b));

    let (mgr_a, _ina) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inb) = ConnectionManager::start(cfg_b).await.unwrap();

    mgr_a
        .add_address(20, PeerAddress::new(loopback(port_b), TransportKind::Tcp))
        .await;
    wait_for_link(&mgr_a, 20, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, 10, TransportKind::Tcp).await;

    // Send BestEffort — only TCP is up, so it must fall back to TCP.
    mgr_a
        .send(
            20,
            ServiceLevel::BestEffort,
            None,
            MessageClass::Regular,
            Bytes::from_static(b"fb"),
        )
        .await
        .unwrap();
    let recv = timeout(Duration::from_secs(2), inb.regular().recv())
        .await
        .expect("recv timeout")
        .expect("channel closed");
    // Frame envelope still carries level=BestEffort but the actual transport
    // is TCP (Reliable).
    assert_eq!(recv.transport(), TransportKind::Tcp);
}

/// Checks UDP packet-encrypted S2S transport establishment and bidirectional delivery.
/// Expected: both nodes install the UDP route and exchange BestEffort frames
/// with the correct peer node id, class, payload, and UDP transport marker.
/// Mumble's client UDP crypt path is in `D:\mumble\src\murmur\Server.cpp::run`;
/// shitspeak's UDP/OCB2 precedent is in `D:\shitspeak\client.go`; this test
/// verifies this crate's S2S encrypted-datagram transport equivalent.
#[tokio::test]
async fn two_node_udp_packet_encryption_roundtrip() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[111, 222]);
    let tcp_port_a = pick_free_port().await;
    let tcp_port_b = pick_free_port().await;
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    let cfg_a = config_with_tcp_and_udp(&pki, 0, loopback(tcp_port_a), loopback(port_a));
    let cfg_b = config_with_tcp_and_udp(&pki, 1, loopback(tcp_port_b), loopback(port_b));

    let (mgr_a, mut inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();
    assert_eq!(mgr_a.local_node_id(), 111);
    assert_eq!(mgr_b.local_node_id(), 222);

    // UDP key exchange is armed only after a reliable route is live.
    mgr_a
        .add_address(
            222,
            PeerAddress::new(loopback(tcp_port_b), TransportKind::Tcp),
        )
        .await;
    wait_for_link(&mgr_a, 222, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, 111, TransportKind::Tcp).await;

    // A learns where to send encrypted UDP packets. B installs the reverse
    // route when it receives a valid signed key offer from A.
    mgr_a
        .add_address(222, PeerAddress::new(loopback(port_b), TransportKind::Udp))
        .await;

    wait_for_link(&mgr_a, 222, TransportKind::Udp).await;
    wait_for_link(&mgr_b, 111, TransportKind::Udp).await;

    // A → B over encrypted UDP.
    mgr_a
        .send(
            222,
            ServiceLevel::BestEffort,
            None,
            MessageClass::HighPriority,
            Bytes::from_static(b"voice-frame-from-a"),
        )
        .await
        .unwrap();
    let recv = timeout(Duration::from_secs(3), inbound_b.high_priority().recv())
        .await
        .expect("a→b encrypted udp recv timeout")
        .expect("a→b channel closed");
    assert_eq!(recv.from(), 111);
    assert_eq!(recv.transport(), TransportKind::Udp);
    assert_eq!(recv.class(), MessageClass::HighPriority);
    assert_eq!(recv.payload().as_ref(), b"voice-frame-from-a");

    // B → A over the reverse encrypted UDP route.
    mgr_b
        .send(
            111,
            ServiceLevel::BestEffort,
            None,
            MessageClass::Regular,
            Bytes::from_static(b"control-frame-from-b"),
        )
        .await
        .unwrap();
    let recv = timeout(Duration::from_secs(3), inbound_a.regular().recv())
        .await
        .expect("b→a encrypted udp recv timeout")
        .expect("b→a channel closed");
    assert_eq!(recv.from(), 222);
    assert_eq!(recv.transport(), TransportKind::Udp);
    assert_eq!(recv.payload().as_ref(), b"control-frame-from-b");

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

#[tokio::test]
async fn simultaneous_udp_packet_encryption_dials_converge() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[121, 232]);
    let tcp_port_a = pick_free_port().await;
    let tcp_port_b = pick_free_port().await;
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    let cfg_a = config_with_tcp_and_udp(&pki, 0, loopback(tcp_port_a), loopback(port_a));
    let cfg_b = config_with_tcp_and_udp(&pki, 1, loopback(tcp_port_b), loopback(port_b));

    let (mgr_a, mut inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();

    mgr_a
        .add_address(
            232,
            PeerAddress::new(loopback(tcp_port_b), TransportKind::Tcp),
        )
        .await;
    wait_for_link(&mgr_a, 232, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, 121, TransportKind::Tcp).await;

    mgr_a
        .add_address(232, PeerAddress::new(loopback(port_b), TransportKind::Udp))
        .await;
    mgr_b
        .add_address(121, PeerAddress::new(loopback(port_a), TransportKind::Udp))
        .await;

    wait_for_link(&mgr_a, 232, TransportKind::Udp).await;
    wait_for_link(&mgr_b, 121, TransportKind::Udp).await;

    mgr_a
        .send(
            232,
            ServiceLevel::BestEffort,
            None,
            MessageClass::Regular,
            Bytes::from_static(b"cross-a"),
        )
        .await
        .unwrap();
    mgr_b
        .send(
            121,
            ServiceLevel::BestEffort,
            None,
            MessageClass::Regular,
            Bytes::from_static(b"cross-b"),
        )
        .await
        .unwrap();

    let recv_b = timeout(Duration::from_secs(3), inbound_b.regular().recv())
        .await
        .expect("a->b simultaneous udp recv timeout")
        .expect("a->b channel closed");
    let recv_a = timeout(Duration::from_secs(3), inbound_a.regular().recv())
        .await
        .expect("b->a simultaneous udp recv timeout")
        .expect("b->a channel closed");

    assert_eq!(recv_b.from(), 121);
    assert_eq!(recv_b.transport(), TransportKind::Udp);
    assert_eq!(recv_b.payload().as_ref(), b"cross-a");
    assert_eq!(recv_a.from(), 232);
    assert_eq!(recv_a.transport(), TransportKind::Udp);
    assert_eq!(recv_a.payload().as_ref(), b"cross-b");

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

#[tokio::test]
async fn simultaneous_kcp_dials_converge_without_tls_role_collision() {
    let _guard = s2s_network_test_guard().await;
    install_provider_once();
    let pki = mint_pki(&[131, 242]);
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    let (cert_a, key_a) = &pki.nodes[0];
    let (cert_b, key_b) = &pki.nodes[1];
    let cfg_a = TransportConfig::new(pki.ca_path.clone(), cert_a.clone(), key_a.clone())
        .with_kcp_listen(loopback(port_a))
        .with_reconnect_check_interval(Duration::from_millis(50))
        .with_backoff_initial(Duration::from_millis(20))
        .with_backoff_cap(Duration::from_millis(500))
        .with_ping_interval(Duration::from_millis(300))
        .with_bandwidth_probe_size(0);
    let cfg_b = TransportConfig::new(pki.ca_path.clone(), cert_b.clone(), key_b.clone())
        .with_kcp_listen(loopback(port_b))
        .with_reconnect_check_interval(Duration::from_millis(50))
        .with_backoff_initial(Duration::from_millis(20))
        .with_backoff_cap(Duration::from_millis(500))
        .with_ping_interval(Duration::from_millis(300))
        .with_bandwidth_probe_size(0);

    let (mgr_a, mut inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();

    mgr_a
        .add_address(242, PeerAddress::new(loopback(port_b), TransportKind::Kcp))
        .await;
    mgr_b
        .add_address(131, PeerAddress::new(loopback(port_a), TransportKind::Kcp))
        .await;

    wait_for_link(&mgr_a, 242, TransportKind::Kcp).await;
    wait_for_link(&mgr_b, 131, TransportKind::Kcp).await;

    mgr_a
        .send(
            242,
            ServiceLevel::ReliableLowLatency,
            None,
            MessageClass::Regular,
            Bytes::from_static(b"kcp-a"),
        )
        .await
        .unwrap();
    mgr_b
        .send(
            131,
            ServiceLevel::ReliableLowLatency,
            None,
            MessageClass::Regular,
            Bytes::from_static(b"kcp-b"),
        )
        .await
        .unwrap();

    let recv_b = timeout(Duration::from_secs(3), inbound_b.regular().recv())
        .await
        .expect("a->b simultaneous kcp recv timeout")
        .expect("a->b channel closed");
    let recv_a = timeout(Duration::from_secs(3), inbound_a.regular().recv())
        .await
        .expect("b->a simultaneous kcp recv timeout")
        .expect("b->a channel closed");

    assert_eq!(recv_b.from(), 131);
    assert_eq!(recv_b.transport(), TransportKind::Kcp);
    assert_eq!(recv_b.payload().as_ref(), b"kcp-a");
    assert_eq!(recv_a.from(), 242);
    assert_eq!(recv_a.transport(), TransportKind::Kcp);
    assert_eq!(recv_a.payload().as_ref(), b"kcp-b");

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;
}

async fn wait_for_link(mgr: &ConnectionManager, node: u16, kind: TransportKind) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Some(per_t) = mgr.metrics_snapshot().for_node(node) {
            if per_t.contains_key(&kind) {
                return;
            }
        }
        // Check via send-probe path: a peer with a live stream will be in the
        // peer table; if not yet, try once and let the supervisor retry.
        if mgr.has_live_transport_kind(node, kind) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("link to {node} via {kind:?} never came up");
}

async fn measure_tcp_wire_efficiency(
    node_a: u16,
    node_b: u16,
    scenario: CompressionScenario,
    warmup: bool,
) -> WireEfficiency {
    let pki = mint_pki(&[node_a, node_b]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let cfg_a = scenario.apply(config_for_compression(&pki, 0, loopback(port_a)));
    let cfg_b = scenario.apply(config_for_compression(&pki, 1, loopback(port_b)));

    let (mgr_a, _inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();

    mgr_a
        .add_address(
            node_b,
            PeerAddress::new(loopback(port_b), TransportKind::Tcp),
        )
        .await;
    wait_for_link(&mgr_a, node_b, TransportKind::Tcp).await;
    wait_for_link(&mgr_b, node_a, TransportKind::Tcp).await;

    if warmup {
        for i in 0..160 {
            send_tcp_compression_sample(&mgr_a, &mut inbound_b, node_b, i).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for i in 160..176 {
            send_tcp_compression_sample(&mgr_a, &mut inbound_b, node_b, i).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let before = tcp_metrics(&mgr_a, node_b);
    for i in 128..152 {
        send_tcp_compression_sample(&mgr_a, &mut inbound_b, node_b, i).await;
    }
    let after = tcp_metrics(&mgr_a, node_b);

    mgr_a.shutdown().await;
    mgr_b.shutdown().await;

    WireEfficiency {
        payload_bytes: after.sent_bytes().saturating_sub(before.sent_bytes()),
        wire_bytes: after
            .wire_sent_bytes()
            .saturating_sub(before.wire_sent_bytes()),
    }
}

async fn send_tcp_compression_sample(
    mgr: &ConnectionManager,
    inbound: &mut Inbound,
    node: u16,
    seq: usize,
) {
    let payload = adaptive_compression_payload(seq);
    mgr.send_via_with_options(
        node,
        TransportKind::Tcp,
        MessageClass::Regular,
        payload.clone(),
        SendOptions::default().allow_l1_compression(),
    )
    .await
    .unwrap();

    let recv = timeout(Duration::from_secs(3), inbound.regular().recv())
        .await
        .expect("adaptive compression recv timeout")
        .expect("adaptive compression recv channel closed");
    assert_eq!(recv.transport(), TransportKind::Tcp);
    assert_eq!(recv.payload(), &payload);
}

fn adaptive_compression_payload(seq: usize) -> Bytes {
    Bytes::from(format!(
        "topic=channels;kind=StrictCatchupResp;server_id=default;\
         origin_node={};snapshot_version={};history_version={};history_freshness=170000{};\
         channel_path=/Root/Team/{}/Room/{};actor_session={};target_session={};\
         permissions=TextMessage,Enter,Speak,Whisper,Traverse;\
         groups=admin,moderator,authenticated,registered;\
         acl_read=true;acl_write=false;codec=opus;comment_hash=0123456789abcdef;\
         plugin_context=overlay-replication-application-transport;\
         checksum={:08x};",
        100 + (seq % 7),
        10_000 + seq,
        50_000 + seq,
        seq % 1000,
        seq % 12,
        seq % 31,
        1_000 + seq,
        2_000 + seq,
        seq.wrapping_mul(2_654_435_761usize) as u32,
    ))
}

fn tcp_metrics(mgr: &ConnectionManager, node: u16) -> LinkMetrics {
    mgr.metrics_snapshot()
        .for_node(node)
        .and_then(|per_transport| per_transport.get(&TransportKind::Tcp))
        .cloned()
        .expect("tcp metrics")
}

async fn wait_for_one_way_tcp_passive_metrics(
    sender_manager: &ConnectionManager,
    sender_node: u16,
    receiver_manager: &ConnectionManager,
    receiver_node: u16,
) -> (LinkMetrics, LinkMetrics) {
    timeout(Duration::from_secs(2), async {
        loop {
            let sender = tcp_metrics(sender_manager, sender_node);
            let receiver = tcp_metrics(receiver_manager, receiver_node);
            if sender.observed_sent_bps() > 0.0
                && sender.observed_recv_bps() == 0.0
                && receiver.observed_recv_bps() > 0.0
                && receiver.observed_sent_bps() == 0.0
            {
                return (sender, receiver);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("one-way TCP passive throughput metrics did not converge")
}
