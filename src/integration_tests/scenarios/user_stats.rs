use std::time::Duration;

use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::messages::encoder::UserStats;
use crate::messages::Message;

#[tokio::test]
async fn user_stats_includes_certificate_chain() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    alice
        .send(
            UserStats {
                session: Some(alice.session_id),
                stats_only: Some(false),
                ..UserStats::default()
            }
            .into(),
        )
        .await;

    let msg = alice
        .recv_until(
            |m| matches!(m, Message::UserStats(us) if us.session == Some(alice.session_id)),
            Duration::from_secs(2),
        )
        .await;

    let Some(Message::UserStats(stats)) = msg else {
        panic!("Alice should receive her UserStats response");
    };

    assert_eq!(stats.certificates.len(), 1);
    assert_eq!(stats.certificates[0].as_ref(), alice.cert_der.as_slice());
    assert_eq!(stats.strong_certificate, Some(true));
}

#[tokio::test]
async fn user_stats_reports_bandwidth_and_idle_time() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    tokio::time::sleep(Duration::from_secs(1)).await;

    alice
        .send(
            UserStats {
                session: Some(alice.session_id),
                stats_only: Some(true),
                ..UserStats::default()
            }
            .into(),
        )
        .await;

    let msg = alice
        .recv_until(
            |m| matches!(m, Message::UserStats(us) if us.session == Some(alice.session_id)),
            Duration::from_secs(2),
        )
        .await;

    let Some(Message::UserStats(stats)) = msg else {
        panic!("Alice should receive her UserStats response");
    };

    assert!(
        stats.bandwidth.unwrap_or_default() > 0,
        "UserStats bandwidth should include observed TCP traffic"
    );
    assert!(
        stats.tcp_packets.unwrap_or_default() > 0,
        "UserStats TCP packet count should include observed TCP frames"
    );
    assert!(
        stats.idlesecs.unwrap_or_default() >= 1,
        "UserStats idle seconds should track time since last client activity"
    );
}
