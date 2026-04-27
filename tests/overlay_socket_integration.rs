//! End-to-end integration tests for [`OverlaySocketRuntime`].
//!
//! Coverage:
//!  1. UDP unicast round-trip (Heartbeat)
//!  2. TCP unicast round-trip (Heartbeat via `send_to`)
//!  3. UDP broadcast to multiple receivers
//!  4. Dynamic peer discovery: register addr after construction, then send
//!  5. Peer removal stops delivery
//!  6. `peer_addrs` reflects register/remove lifecycle
//!  7. `drain_incoming` respects max-items limit
//!  8. `frame_len` in `InboundEnvelope` matches actual wire bytes
//!  9. Malformed UDP frame is silently skipped; valid frame still arrives
//! 10. All `ClusterMessage` variants survive socket round-trip
//! 11. `send_to` is unicast – only the target peer receives the frame
//! 12. TCP acceptor handles multiple frames sent on a single connection
//! 13. `recv_next` blocks until a frame arrives

use std::net::SocketAddr;

use shitspeak_rs::s2s::{
    ApplicationLayer3Message, ClusterEnvelope, ClusterMessage, ConsensusLayer2Message,
    InboundEnvelope, MemberRecord, MemberState, MessageMode, NodePresenceDelta,
    OverlaySocketRuntime, RouteClass, RoutePath, SelectedTransport, TransportKind,
};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Duration};

// ─── helpers ──────────────────────────────────────────────────────────────────

fn heartbeat(from: u16) -> ClusterEnvelope {
    ClusterEnvelope {
        version: 1,
        feature_bitmap: 0,
        from,
        seq: 1,
        mode: MessageMode::Broadcast,
        body: ClusterMessage::Heartbeat {
            boot_id: format!("boot-{from}"),
            members_seen: 1,
        },
    }
}

fn udp_transport() -> SelectedTransport {
    SelectedTransport { primary: TransportKind::Udp, fallback: None }
}

fn tcp_transport() -> SelectedTransport {
    SelectedTransport { primary: TransportKind::TlsTcp, fallback: None }
}

/// Poll `drain_incoming` in a loop, appending each batch, until
/// the predicate `done(collected)` returns true or the timeout elapses.
async fn collect_until(
    runtime: &OverlaySocketRuntime,
    predicate: impl Fn(&[InboundEnvelope]) -> bool,
) -> Vec<InboundEnvelope> {
    let deadline = Duration::from_millis(2_000);
    let mut collected: Vec<InboundEnvelope> = Vec::new();
    let _ = timeout(deadline, async {
        while !predicate(&collected) {
            collected.extend(runtime.drain_incoming(64).await);
            if !predicate(&collected) {
                sleep(Duration::from_millis(5)).await;
            }
        }
    })
    .await;
    collected
}

// ─── test 1: UDP unicast round-trip ──────────────────────────────────────────

#[tokio::test]
async fn udp_send_receive_heartbeat() {
    let receiver = OverlaySocketRuntime::bind(2, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver should bind");
    let receiver_addr = receiver.udp_local_addr().expect("udp addr must be set");

    let sender = OverlaySocketRuntime::bind(
        1,
        Some("127.0.0.1:0"),
        None,
        &[receiver_addr.to_string()],
    )
    .await
    .expect("sender should bind");

    let sent = sender
        .send_envelope(&heartbeat(1), RouteClass::BestEffort, Some(udp_transport()))
        .await
        .expect("send should not error");
    assert_eq!(sent, 1, "one peer should have been reached");

    let got = collect_until(&receiver, |c| c.len() >= 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].envelope.from, 1);
    assert!(matches!(got[0].envelope.body, ClusterMessage::Heartbeat { .. }));
}

// ─── test 2: TCP unicast round-trip ──────────────────────────────────────────

#[tokio::test]
async fn tcp_send_receive_heartbeat() {
    let receiver = OverlaySocketRuntime::bind(4, None, Some("127.0.0.1:0"), &[])
        .await
        .expect("receiver should bind");
    let receiver_tcp = receiver.tcp_local_addr().expect("tcp addr must be set");

    // sender does not need to listen; passes empty slices for both listeners
    let sender =
        OverlaySocketRuntime::bind(3, Some("127.0.0.1:0"), None, &[])
            .await
            .expect("sender should bind");

    let delivered = sender
        .send_to(receiver_tcp, &heartbeat(3), RouteClass::Reliable, Some(tcp_transport()))
        .await
        .expect("send_to should not error");
    assert!(delivered, "TCP frame should be delivered");

    let got = collect_until(&receiver, |c| c.len() >= 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].envelope.from, 3);
    assert!(matches!(got[0].envelope.body, ClusterMessage::Heartbeat { .. }));
}

// ─── test 3: UDP broadcast to multiple receivers ─────────────────────────────

#[tokio::test]
async fn udp_broadcast_reaches_multiple_receivers() {
    let r1 = OverlaySocketRuntime::bind(10, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("r1 should bind");
    let r2 = OverlaySocketRuntime::bind(11, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("r2 should bind");
    let addr1 = r1.udp_local_addr().unwrap();
    let addr2 = r2.udp_local_addr().unwrap();

    let sender = OverlaySocketRuntime::bind(
        9,
        Some("127.0.0.1:0"),
        None,
        &[addr1.to_string(), addr2.to_string()],
    )
    .await
    .expect("sender should bind");

    let sent = sender
        .send_envelope(&heartbeat(9), RouteClass::BestEffort, Some(udp_transport()))
        .await
        .expect("send should not error");
    assert_eq!(sent, 2, "both peers should be reached");

    let got1 = collect_until(&r1, |c| c.len() >= 1).await;
    let got2 = collect_until(&r2, |c| c.len() >= 1).await;
    assert_eq!(got1.len(), 1);
    assert_eq!(got2.len(), 1);
}

// ─── test 4: dynamic peer registration then send ─────────────────────────────

#[tokio::test]
async fn dynamic_peer_register_then_send() {
    let receiver = OverlaySocketRuntime::bind(20, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver should bind");
    let receiver_addr = receiver.udp_local_addr().unwrap();

    // sender starts with NO peers
    let sender = OverlaySocketRuntime::bind(19, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("sender should bind");

    // confirm nothing sent to empty peer list
    let sent_before = sender
        .send_envelope(&heartbeat(19), RouteClass::BestEffort, Some(udp_transport()))
        .await
        .expect("send should not error");
    assert_eq!(sent_before, 0);

    sender.register_peer_addr(receiver_addr).await;

    let sent_after = sender
        .send_envelope(&heartbeat(19), RouteClass::BestEffort, Some(udp_transport()))
        .await
        .expect("send should not error");
    assert_eq!(sent_after, 1);

    let got = collect_until(&receiver, |c| c.len() >= 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].envelope.from, 19);
}

// ─── test 5: remove_peer stops delivery ──────────────────────────────────────

#[tokio::test]
async fn remove_peer_stops_delivery() {
    let receiver = OverlaySocketRuntime::bind(30, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver should bind");
    let receiver_addr = receiver.udp_local_addr().unwrap();

    let sender = OverlaySocketRuntime::bind(
        29,
        Some("127.0.0.1:0"),
        None,
        &[receiver_addr.to_string()],
    )
    .await
    .expect("sender should bind");

    // confirm delivery works before removal
    let sent_before = sender
        .send_envelope(&heartbeat(29), RouteClass::BestEffort, Some(udp_transport()))
        .await
        .unwrap();
    assert_eq!(sent_before, 1);
    let _ = collect_until(&receiver, |c| c.len() >= 1).await;

    // remove peer and resend
    let removed = sender.remove_peer_addr(receiver_addr).await;
    assert!(removed, "peer should have been found and removed");

    let sent_after = sender
        .send_envelope(&heartbeat(29), RouteClass::BestEffort, Some(udp_transport()))
        .await
        .unwrap();
    assert_eq!(sent_after, 0, "no peers remain; nothing should be sent");

    // removing non-existent peer returns false
    let removed_again = sender.remove_peer_addr(receiver_addr).await;
    assert!(!removed_again);
}

// ─── test 6: peer_addrs reflects lifecycle ───────────────────────────────────

#[tokio::test]
async fn peer_addrs_reflects_register_and_remove() {
    let addr_a: SocketAddr = "127.0.0.1:19001".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:19002".parse().unwrap();
    let addr_c: SocketAddr = "127.0.0.1:19003".parse().unwrap();

    let runtime =
        OverlaySocketRuntime::bind(50, Some("127.0.0.1:0"), None, &[addr_a.to_string()])
            .await
            .expect("should bind");

    // bootstrap gives us addr_a
    assert_eq!(runtime.peer_addrs().await, vec![addr_a]);

    // register_peer_addr adds addr_b
    runtime.register_peer_addr(addr_b).await;
    let mut peers = runtime.peer_addrs().await;
    peers.sort();
    assert_eq!(peers, {
        let mut expected = vec![addr_a, addr_b];
        expected.sort();
        expected
    });

    // register same addr again is idempotent
    runtime.register_peer_addr(addr_a).await;
    let mut peers = runtime.peer_addrs().await;
    peers.sort();
    assert_eq!(peers.len(), 2);

    // register addr_c then remove addr_a
    runtime.register_peer_addr(addr_c).await;
    assert_eq!(runtime.peer_addrs().await.len(), 3);
    runtime.remove_peer_addr(addr_a).await;
    let mut peers = runtime.peer_addrs().await;
    peers.sort();
    assert_eq!(peers, {
        let mut expected = vec![addr_b, addr_c];
        expected.sort();
        expected
    });
}

// ─── test 7: drain_incoming respects max-items ───────────────────────────────

#[tokio::test]
async fn drain_incoming_respects_max_items_limit() {
    let receiver = OverlaySocketRuntime::bind(60, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver should bind");
    let receiver_addr = receiver.udp_local_addr().unwrap();

    let sender = OverlaySocketRuntime::bind(
        59,
        Some("127.0.0.1:0"),
        None,
        &[receiver_addr.to_string()],
    )
    .await
    .expect("sender should bind");

    // send 5 frames
    for _ in 0..5 {
        sender
            .send_envelope(&heartbeat(59), RouteClass::BestEffort, Some(udp_transport()))
            .await
            .unwrap();
    }

    // wait for all 5 to arrive
    let all = collect_until(&receiver, |c| c.len() >= 5).await;
    assert_eq!(all.len(), 5, "all 5 frames should arrive");

    // ── fresh receiver for drain-limit test ──
    let receiver2 = OverlaySocketRuntime::bind(62, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver2 should bind");
    let addr2 = receiver2.udp_local_addr().unwrap();
    sender.register_peer_addr(addr2).await;

    for _ in 0..5 {
        sender
            .send_envelope(&heartbeat(59), RouteClass::BestEffort, Some(udp_transport()))
            .await
            .unwrap();
    }

    // wait until queue has all 5
    let _ = collect_until(&receiver2, |c| c.len() >= 5).await;
    // Nothing left to drain — test drain-limit on a new batch
    // Re-send 5 more frames
    for _ in 0..5 {
        sender
            .send_envelope(&heartbeat(59), RouteClass::BestEffort, Some(udp_transport()))
            .await
            .unwrap();
    }
    // generous wait
    sleep(Duration::from_millis(100)).await;

    let batch_a = receiver2.drain_incoming(3).await;
    assert_eq!(batch_a.len(), 3);

    let batch_b = receiver2.drain_incoming(10).await;
    assert_eq!(batch_b.len(), 2);

    let batch_c = receiver2.drain_incoming(10).await;
    assert_eq!(batch_c.len(), 0, "queue should be empty after draining all items");
}

// ─── test 8: frame_len matches wire bytes ────────────────────────────────────

#[tokio::test]
async fn frame_len_in_inbound_matches_wire_bytes() {
    let receiver = OverlaySocketRuntime::bind(70, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver should bind");
    let receiver_addr = receiver.udp_local_addr().unwrap();

    let sender = OverlaySocketRuntime::bind(
        69,
        Some("127.0.0.1:0"),
        None,
        &[receiver_addr.to_string()],
    )
    .await
    .expect("sender should bind");

    let env = heartbeat(69);
    sender
        .send_envelope(&env, RouteClass::BestEffort, Some(udp_transport()))
        .await
        .unwrap();

    let got = collect_until(&receiver, |c| c.len() >= 1).await;
    let stamped = {
        let mut e = env.clone();
        e.from = 69; // sender stamps local_node
        e
    };
    let expected_len = serde_json::to_vec(&stamped).unwrap().len();
    assert_eq!(got[0].frame_len, expected_len);
}

// ─── test 9: malformed UDP frame skipped, valid frame still arrives ──────────

#[tokio::test]
async fn malformed_udp_frame_skipped_without_panic() {
    let receiver = OverlaySocketRuntime::bind(80, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver should bind");
    let receiver_addr = receiver.udp_local_addr().unwrap();

    // send garbage via raw socket
    let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    raw.send_to(b"THIS IS NOT JSON {{{", receiver_addr).await.unwrap();

    // now send a real frame
    let sender = OverlaySocketRuntime::bind(
        79,
        Some("127.0.0.1:0"),
        None,
        &[receiver_addr.to_string()],
    )
    .await
    .expect("sender should bind");
    sender
        .send_envelope(&heartbeat(79), RouteClass::BestEffort, Some(udp_transport()))
        .await
        .unwrap();

    let got = collect_until(&receiver, |c| c.len() >= 1).await;
    // only the valid frame should appear
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].envelope.from, 79);
}

// ─── test 10: all ClusterMessage variants survive socket round-trip ──────────

#[tokio::test]
async fn all_cluster_message_variants_roundtrip_through_udp() {
    let receiver = OverlaySocketRuntime::bind(90, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver should bind");
    let receiver_addr = receiver.udp_local_addr().unwrap();

    let sender = OverlaySocketRuntime::bind(
        89,
        Some("127.0.0.1:0"),
        None,
        &[receiver_addr.to_string()],
    )
    .await
    .expect("sender should bind");

    let variants: Vec<ClusterMessage> = vec![
        ClusterMessage::Heartbeat {
            boot_id: "b1".to_owned(),
            members_seen: 3,
        },
        ClusterMessage::MembershipUpdate {
            record: MemberRecord {
                node_id: 5,
                state: MemberState::Alive,
                incarnation: 2,
                last_seen_ms: 1_000,
                boot_id: "b2".to_owned(),
            },
        },
        ClusterMessage::NodePresence {
            delta: NodePresenceDelta::MetadataUpsert {
                node_id: 7,
                key: "region".to_owned(),
                value: "us-east".to_owned(),
                updated_ms: 2_000,
            },
        },
        ClusterMessage::PeerList {
            peers: vec!["127.0.0.1:9001".to_owned(), "127.0.0.1:9002".to_owned()],
        },
        ClusterMessage::DataForward {
            route_class: RouteClass::Reliable,
            path: RoutePath::Direct { target: 3 },
            stream_id: 42,
            sequence: 7,
            path_trace: vec![1, 2],
            content_type: "application/octet-stream".to_owned(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        },
        ClusterMessage::Layer2 {
            message: ConsensusLayer2Message::Layer3 {
                message: ApplicationLayer3Message::Replication {
                    payload: b"layer3-repl-payload".to_vec(),
                },
            },
        },
    ];

    let count = variants.len();
    for (i, body) in variants.into_iter().enumerate() {
        let env = ClusterEnvelope {
            version: 1,
            feature_bitmap: 0,
            from: 89,
            seq: i as u64,
            mode: MessageMode::Broadcast,
            body,
        };
        sender
            .send_envelope(&env, RouteClass::BestEffort, Some(udp_transport()))
            .await
            .unwrap();
    }

    let got = collect_until(&receiver, |c| c.len() >= count).await;
    assert_eq!(got.len(), count, "all {count} variants should arrive");

    // spot-check a couple of variants that are easy to match by seq
    let seqs: Vec<u64> = got.iter().map(|g| g.envelope.seq).collect();
    for expected_seq in 0..count as u64 {
        assert!(seqs.contains(&expected_seq), "seq {expected_seq} missing");
    }
}

// ─── test 11: send_to is unicast ─────────────────────────────────────────────

#[tokio::test]
async fn send_to_delivers_only_to_target_peer() {
    let r1 = OverlaySocketRuntime::bind(100, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("r1 should bind");
    let r2 = OverlaySocketRuntime::bind(101, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("r2 should bind");
    let addr1 = r1.udp_local_addr().unwrap();

    let sender = OverlaySocketRuntime::bind(99, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("sender should bind");

    // send only to r1 using send_to (udp)
    let delivered = sender
        .send_to(addr1, &heartbeat(99), RouteClass::BestEffort, Some(udp_transport()))
        .await
        .unwrap();
    assert!(delivered);

    // r1 receives the frame
    let got1 = collect_until(&r1, |c| c.len() >= 1).await;
    assert_eq!(got1.len(), 1);

    // r2 receives nothing (wait 100 ms)
    sleep(Duration::from_millis(100)).await;
    let got2 = r2.drain_incoming(10).await;
    assert!(got2.is_empty(), "r2 should not receive a frame directed at r1");
}

// ─── test 12: TCP acceptor handles multiple frames on same connection ────────

#[tokio::test]
async fn tcp_acceptor_handles_multiple_frames_same_connection() {
    let receiver = OverlaySocketRuntime::bind(110, None, Some("127.0.0.1:0"), &[])
        .await
        .expect("receiver should bind");
    let tcp_addr = receiver.tcp_local_addr().expect("tcp addr must be set");

    // manually write 3 newline-delimited JSON frames on one TCP connection
    let mut stream = tokio::net::TcpStream::connect(tcp_addr)
        .await
        .expect("TCP connect should succeed");

    for i in 0u64..3 {
        let env = ClusterEnvelope {
            version: 1,
            feature_bitmap: 0,
            from: 110,
            seq: i,
            mode: MessageMode::Unicast,
            body: ClusterMessage::PeerList { peers: vec![format!("peer-{i}")] },
        };
        let mut frame = serde_json::to_vec(&env).unwrap();
        frame.push(b'\n');
        stream.write_all(&frame).await.expect("write should succeed");
    }
    drop(stream);

    let got = collect_until(&receiver, |c| c.len() >= 3).await;
    assert_eq!(got.len(), 3, "all 3 frames from the same TCP connection should arrive");
    let seqs: Vec<u64> = got.iter().map(|g| g.envelope.seq).collect();
    for expected in 0u64..3 {
        assert!(seqs.contains(&expected), "seq {expected} missing");
    }
}

// ─── test 13: recv_next blocks until a frame arrives ─────────────────────────

#[tokio::test]
async fn recv_next_blocks_until_frame_arrives() {
    let receiver = OverlaySocketRuntime::bind(120, Some("127.0.0.1:0"), None, &[])
        .await
        .expect("receiver should bind");
    let receiver_addr = receiver.udp_local_addr().unwrap();

    // spawn a task that sleeps briefly, then sends a frame
    let sender_task = tokio::spawn(async move {
        sleep(Duration::from_millis(40)).await;
        let sender = OverlaySocketRuntime::bind(
            119,
            Some("127.0.0.1:0"),
            None,
            &[receiver_addr.to_string()],
        )
        .await
        .expect("sender should bind");
        sender
            .send_envelope(
                &heartbeat(119),
                RouteClass::BestEffort,
                Some(udp_transport()),
            )
            .await
            .expect("send should not error");
    });

    // recv_next blocks until the sender delivers the frame
    let result = timeout(Duration::from_millis(1_000), receiver.recv_next())
        .await
        .expect("recv_next should not time out");

    let frame = result.expect("channel should not close");
    assert_eq!(frame.envelope.from, 119);

    sender_task.await.unwrap();
}
