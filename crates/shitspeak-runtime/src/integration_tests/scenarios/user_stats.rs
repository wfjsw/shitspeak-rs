use std::time::Duration;

use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use shitspeak_messages::messages::Message;
use shitspeak_messages::messages::encoder::{Ping, UserStats};
use shitspeak_state::Channel;
use shitspeak_state::{ACL, ACLPermissions};

#[tokio::test]
async fn user_stats_omits_sensitive_fields_for_non_superuser() {
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

    assert!(stats.certificates.is_empty());
    assert_eq!(stats.address, None);
    let version = stats.version.as_ref().expect("version should be present");
    assert!(version.version_v1.is_some() || version.version_v2.is_some());
    assert_eq!(version.release, None);
    assert_eq!(version.os, None);
    assert_eq!(version.os_version, None);
    assert_eq!(stats.strong_certificate, Some(true));
}

#[tokio::test]
async fn user_stats_includes_sensitive_fields_for_superuser() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_superuser("alice", None, Some(1), vec!["admin".into()]);

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
    assert!(stats.address.is_some());
    let version = stats.version.as_ref().expect("version should be present");
    assert_eq!(version.release.as_deref(), Some("test-client"));
    assert_eq!(version.os.as_deref(), Some("test"));
    assert_eq!(version.os_version.as_deref(), Some("test"));
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
            Ping {
                timestamp: 1,
                tcp_packets: Some(1),
                ..Ping::default()
            }
            .into(),
        )
        .await;
    alice
        .recv_until(
            |m| matches!(m, Message::Ping(ping) if ping.timestamp == Some(1)),
            Duration::from_secs(2),
        )
        .await
        .expect("Alice should receive her Ping response");
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
    assert_eq!(
        stats.tcp_packets,
        Some(1),
        "UserStats TCP packet count should reflect Ping.tcp_packets, not all observed TCP frames"
    );
    assert!(
        stats.idlesecs.unwrap_or_default() >= 1,
        "UserStats idle seconds should track time since last client activity"
    );
}

#[tokio::test]
async fn user_stats_reports_udp_network_statistics() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);

    let mut alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    alice.open_udp().await.expect("alice udp bind");
    alice.udp_handshake().await.expect("alice udp handshake");
    alice
        .recv_udp_ping(Duration::from_secs(2))
        .await
        .expect("encrypted UDP ping response");

    alice
        .send(
            Ping {
                timestamp: 42,
                good: 7,
                late: 2,
                lost: 3,
                resync: 4,
                ..Ping::default()
            }
            .into(),
        )
        .await;
    alice
        .recv_until(
            |m| matches!(m, Message::Ping(ping) if ping.timestamp == Some(42)),
            Duration::from_secs(2),
        )
        .await
        .expect("Alice should receive her Ping response");

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

    let from_client = stats
        .from_client
        .expect("UserStats should include UDP stats for packets from the client");
    assert!(
        from_client.good.unwrap_or_default() >= 1,
        "server-side UDP stats should include the authenticated handshake packet"
    );
    assert_eq!(from_client.late, Some(0));
    assert_eq!(from_client.lost, Some(0));
    assert_eq!(from_client.resync, Some(0));

    let from_server = stats
        .from_server
        .expect("UserStats should include UDP stats reported by the client");
    assert_eq!(from_server.good, Some(7));
    assert_eq!(from_server.late, Some(2));
    assert_eq!(from_server.lost, Some(3));
    assert_eq!(from_server.resync, Some(4));
    assert!(
        stats.udp_packets.unwrap_or_default() >= 1,
        "UserStats UDP packet count should include observed encrypted UDP traffic"
    );
}

#[tokio::test]
async fn user_stats_requires_enter_on_target_channel_without_root_ban() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec![]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(80, "Hidden".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .set_acls(
            80,
            true,
            vec![ACL {
                user_id: Some(1),
                group: None,
                apply_here: true,
                apply_subs: false,
                allow: enumflags2::BitFlags::empty(),
                deny: ACLPermissions::Enter.into(),
            }],
        )
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(80).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

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

    let denied = alice
        .recv_until(
            |m| {
                matches!(m, Message::PermissionDenied(pd)
                    if pd.channel_id == Some(80)
                        && pd.permission == Some(ACLPermissions::Enter as u32))
            },
            Duration::from_secs(2),
        )
        .await;
    assert!(
        denied.is_some(),
        "UserStats should require Enter on the target user's channel"
    );
}
