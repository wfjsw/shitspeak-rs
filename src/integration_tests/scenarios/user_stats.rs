use std::time::Duration;

use crate::acl::{ACL, ACLPermissions};
use crate::channels::Channel;
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::messages::Message;
use crate::messages::encoder::UserStats;

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
