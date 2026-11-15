//! Observability surface scenarios: what a scrape actually emits.
//!
//! The unit tests cover the series builders; this proves the wiring end to
//! end — real UDP voice frames and a real client `Ping` reach the exposition
//! *with values*, and the same series reach remote write. Label presence alone
//! would be satisfied by an all-zero link, so every assertion here pins a
//! number the traffic is responsible for.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::integration_tests::harness::{
    SAMPLE_OPUS, TestClient, TestServer, TestServerOpts, spawn_test_server,
};
use crate::messages::encoder::Ping;
use crate::observability::{S2sMetricsSource, ServerMetricsSource};

/// Downlink statistics the client claims in its ping. Absolute values, so the
/// server must echo exactly these into the `downlink` series.
const REPORTED_GOOD: u32 = 100;
const REPORTED_LOST: u32 = 2;

fn metrics_source(server: &TestServer) -> ServerMetricsSource {
    ServerMetricsSource::new(
        server.server.s2s_manager().clone(),
        server.server.get_clients().clone(),
        server.server.get_channels().clone(),
        Arc::downgrade(&server.server),
    )
}

/// Value of one `shitspeak_client_udp_packets_total` series; panics when the
/// series is absent, so a missing label can never read as zero.
fn udp_counter(text: &str, session: u32, direction: &str, result: &str) -> f64 {
    let line = text
        .lines()
        .find(|line| {
            line.starts_with("shitspeak_client_udp_packets_total{")
                && line.contains(&format!("session=\"{session}\""))
                && line.contains(&format!("direction=\"{direction}\""))
                && line.contains(&format!("result=\"{result}\""))
        })
        .unwrap_or_else(|| panic!("no {direction}/{result} series for session {session}:\n{text}"));
    line.rsplit_once('}')
        .and_then(|(_, value)| value.trim().parse().ok())
        .expect("counter value")
}

/// Unpack the crate's literal-only snappy framing back into protobuf bytes.
///
/// The framing is the uncompressed-length varint followed by literal blocks,
/// each a tag byte `(len - 1) << 2` with `len <= 60` and then the bytes.
fn decode_snappy_literals(body: &[u8]) -> Vec<u8> {
    let mut rest = body;
    // Skip the uncompressed-length varint; its value frame is not needed here.
    while let Some((byte, tail)) = rest.split_first() {
        rest = tail;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let mut out = Vec::new();
    while let Some((tag, tail)) = rest.split_first() {
        if tag & 0b11 != 0 {
            break;
        }
        let len = usize::from(tag >> 2) + 1;
        let len = len.min(tail.len());
        out.extend_from_slice(&tail[..len]);
        rest = &tail[len..];
    }
    out
}

#[tokio::test]
async fn a_udp_client_reaches_the_scrape_with_its_link_attribution() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let mut alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    alice.open_udp().await.expect("udp socket");
    alice.udp_handshake().await.expect("udp handshake");
    // The encrypted echo is the bind barrier: the server answered only after
    // it decrypted the handshake, so the client's UDP address is bound and its
    // crypt state exists before the first scrape.
    alice
        .recv_udp_ping(Duration::from_secs(2))
        .await
        .expect("udp ping echo");

    for frame in 0..2 {
        alice
            .send_voice_udp(0, frame, Bytes::from_static(SAMPLE_OPUS))
            .await
            .expect("voice frame");
    }
    // A ping carrying downlink counters; its own reply is the barrier that the
    // handler stored them.
    alice
        .send(
            Ping {
                timestamp: 1,
                good: REPORTED_GOOD,
                late: 1,
                lost: REPORTED_LOST,
                resync: 3,
                ..Ping::default()
            }
            .into(),
        )
        .await;
    assert!(
        alice
            .recv_until(
                |message| matches!(message, crate::messages::Message::Ping(_)),
                Duration::from_secs(2)
            )
            .await
            .is_some(),
        "ping reply missing"
    );

    let session = alice.session_id;
    let source = metrics_source(&server);
    // Frames are decrypted asynchronously; scrape until they are counted.
    let mut text = String::new();
    for _ in 0..100 {
        text = source
            .prometheus_metrics_text()
            .await
            .expect("metrics text");
        if udp_counter(&text, session, "uplink", "good") >= 2.0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Uplink counts what we actually sent: the two voice frames plus the
    // handshake ping.
    assert!(
        udp_counter(&text, session, "uplink", "good") >= 2.0,
        "the voice frames were never decrypted and counted:\n{text}"
    );
    // Downlink counts what the client reported, verbatim.
    assert_eq!(
        udp_counter(&text, session, "downlink", "good"),
        f64::from(REPORTED_GOOD)
    );
    assert_eq!(
        udp_counter(&text, session, "downlink", "lost"),
        f64::from(REPORTED_LOST)
    );
    // The loss gauge divides those counters (2 of 103 never arrived).
    let ratio = text
        .lines()
        .find(|line| {
            line.starts_with("shitspeak_client_udp_packet_loss_ratio{")
                && line.contains(&format!("session=\"{session}\""))
                && line.contains("direction=\"downlink\"")
        })
        .and_then(|line| line.rsplit_once('}'))
        .and_then(|(_, value)| value.trim().parse::<f64>().ok())
        .expect("downlink loss ratio");
    assert!((ratio - 2.0 / 103.0).abs() < 1e-9, "ratio {ratio}");

    // Loopback traffic has no public address: the geo labels must be present
    // and unknown, never absent, so `sum by (region)` cannot lose the client.
    assert!(text.contains("region=\"unknown\""), "{text}");
    assert!(text.contains("subnet=\"127.0.0.0/24\""), "{text}");
    // The city bucket carries the same client, count 1, coordinates empty.
    assert!(
        text.lines()
            .any(|line| line.starts_with("shitspeak_clients_by_city{")
                && line.contains("city=\"unknown\"")
                && line.contains("lat=\"\"")
                && line.trim_end().ends_with(" 1")),
        "city gauge missing or not counting the client:\n{text}"
    );

    // The same series must reach remote write, not just the text endpoint.
    let bodies = source
        .prometheus_remote_write_requests(500, &HashMap::new())
        .await
        .expect("remote write bodies");
    // Remote write carries labels as separate protobuf strings, so the decoded
    // body holds the metric name and the session value unquoted.
    let decoded = bodies
        .iter()
        .map(|body| String::from_utf8_lossy(&decode_snappy_literals(body)).into_owned())
        .collect::<Vec<_>>();
    assert!(
        decoded.iter().any(|body| {
            body.contains("shitspeak_client_udp_packets_total")
                && body.contains(&session.to_string())
        }),
        "the udp series never reached remote write; decoded sizes {:?}",
        decoded.iter().map(String::len).collect::<Vec<_>>()
    );

    server.shutdown_gracefully().await;
}
