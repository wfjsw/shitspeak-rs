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

use super::config::TransportConfig;
use super::manager::{ConnectionManager, Inbound};
use super::service_level::{MessageClass, PeerAddress, ServiceLevel, TransportKind};
use crate::s2s::testing::{
    install_provider_once, loopback, mint_pki, pick_free_port, pick_free_udp_port, Pki,
};

/// Serializes tests in this file so concurrent `pick_free_port` calls can't
/// hand the same OS-ephemeral port to two managers before either binds it.
/// On Windows that race surfaces as `WSAEADDRINUSE` (10048).
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

fn config_with_udp(pki: &Pki, node_idx: usize, udp: SocketAddr) -> TransportConfig {
    let (cert, key) = &pki.nodes[node_idx];
    TransportConfig::new(pki.ca_path.clone(), cert.clone(), key.clone())
        .with_udp_listen(udp)
        .with_reconnect_check_interval(Duration::from_millis(50))
        .with_backoff_initial(Duration::from_millis(20))
        .with_backoff_cap(Duration::from_millis(500))
        .with_ping_interval(Duration::from_millis(300))
        .with_bandwidth_probe_interval(Duration::from_secs(60)) // off for these tests
        .with_bandwidth_probe_size(0)
        .with_udp_mtu(1400)
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
    let _guard = TEST_LOCK.lock().await;
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

/// Checks that idle transport probes produce a usable goodput metric.
/// Expected: after service-shaped probe round trips, TCP probe goodput is
/// positive and the estimated throughput is at least that probe-only value. The expected
/// behavior is local to this crate's S2S transport health model; the reference
/// projects provide the surrounding server model (`D:\mumble\src\murmur`) and
/// shitspeak's side-channel precedent (`D:\shitspeak\slavehub.go`).
#[tokio::test]
async fn probe_throughput_reports_idle_link_bandwidth() {
    let _guard = TEST_LOCK.lock().await;
    install_provider_once();
    let pki = mint_pki(&[100, 200]);
    let port_a = pick_free_port().await;
    let port_b = pick_free_port().await;
    let cfg_a = config_for(&pki, 0, loopback(port_a));
    let cfg_b = config_for(&pki, 1, loopback(port_b));

    let (mgr_a, _ina) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, _inb) = ConnectionManager::start(cfg_b).await.unwrap();

    mgr_a
        .add_address(200, PeerAddress::new(loopback(port_b), TransportKind::Tcp))
        .await;
    wait_for_link(&mgr_a, 200, TransportKind::Tcp).await;

    // Idle the link: send no Data frames; let the periodic probe drive
    // the goodput metric. The probe interval is 200ms; we wait long
    // enough to register multiple round trips.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        if let Some(per_t) = mgr_a.metrics_snapshot().for_node(200) {
            if let Some(tcp) = per_t.get(&TransportKind::Tcp) {
                if tcp.probe_samples() >= 2 {
                    // We got at least two probe round trips; throughput EWMA
                    // should be nonzero. On loopback this will be a very
                    // large number — we just verify it is positive.
                    assert!(
                        tcp.max_probe_goodput_bps() > 0.0,
                        "max_probe_goodput_bps should be positive after probes"
                    );
                    assert!(
                        tcp.estimated_throughput_bps() >= tcp.max_probe_goodput_bps(),
                        "estimate should not be less than probe alone"
                    );
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never recorded a probe round trip");
}

/// Checks service-level fallback when only TCP is available.
/// Expected: a BestEffort frame is still delivered over TCP, with the received
/// frame recording TCP as the actual transport. This is this crate's S2S
/// transport policy, built to carry Mumble/shitspeak server messages even when
/// an unreliable path is unavailable.
#[tokio::test]
async fn upward_fallback_uses_tcp_for_best_effort() {
    let _guard = TEST_LOCK.lock().await;
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

/// Checks UDP/DTLS S2S transport establishment and bidirectional delivery.
/// Expected: both nodes install the DTLS session and exchange BestEffort frames
/// with the correct peer node id, class, payload, and UDP transport marker.
/// Mumble's client UDP crypt path is in `D:\mumble\src\murmur\Server.cpp::run`;
/// shitspeak's UDP/OCB2 precedent is in `D:\shitspeak\client.go`; this test
/// verifies this crate's S2S DTLS transport equivalent.
#[tokio::test]
async fn two_node_udp_dtls_roundtrip() {
    let _guard = TEST_LOCK.lock().await;
    install_provider_once();
    let pki = mint_pki(&[111, 222]);
    let port_a = pick_free_udp_port().await;
    let port_b = pick_free_udp_port().await;
    let cfg_a = config_with_udp(&pki, 0, loopback(port_a));
    let cfg_b = config_with_udp(&pki, 1, loopback(port_b));

    let (mgr_a, mut inbound_a) = ConnectionManager::start(cfg_a).await.unwrap();
    let (mgr_b, mut inbound_b) = ConnectionManager::start(cfg_b).await.unwrap();
    assert_eq!(mgr_a.local_node_id(), 111);
    assert_eq!(mgr_b.local_node_id(), 222);

    // A learns where to dial B; the supervisor will run a DTLS client
    // handshake. Once the handshake completes B's listener also installs
    // the session into its peer table.
    mgr_a
        .add_address(222, PeerAddress::new(loopback(port_b), TransportKind::Udp))
        .await;

    wait_for_link(&mgr_a, 222, TransportKind::Udp).await;
    wait_for_link(&mgr_b, 111, TransportKind::Udp).await;

    // A → B over DTLS
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
        .expect("a→b udp dtls recv timeout")
        .expect("a→b channel closed");
    assert_eq!(recv.from(), 111);
    assert_eq!(recv.transport(), TransportKind::Udp);
    assert_eq!(recv.class(), MessageClass::HighPriority);
    assert_eq!(recv.payload().as_ref(), b"voice-frame-from-a");

    // B → A over the same DTLS session
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
        .expect("b→a udp dtls recv timeout")
        .expect("b→a channel closed");
    assert_eq!(recv.from(), 222);
    assert_eq!(recv.transport(), TransportKind::Udp);
    assert_eq!(recv.payload().as_ref(), b"control-frame-from-b");

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
        if let Some(p) = mgr.inner.get_peer(node) {
            if p.live_kinds().contains(&kind) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("link to {node} via {kind:?} never came up");
}
