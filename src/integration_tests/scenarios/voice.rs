//! Voice routing scenarios.
//!
//! Each scenario exists in two flavors: TCP-tunneled (sender writes
//! `Message::UDPTunnel`, server fans out to the per-recipient TCP voice
//! queue) and real UDP (sender encrypts with OCB2 and sends via a UDP
//! socket; recipient receives, decrypts, decodes).

use std::time::Duration;

use bytes::Bytes;

use crate::channels::Channel;
use crate::integration_tests::harness::{spawn_test_server, TestClient, TestServerOpts};
use crate::protocol_version::ProtocolVersion;
use crate::voice::codec::PacketFormat;

const VOICE_DEADLINE: Duration = Duration::from_secs(2);
const NEGATIVE_WINDOW: Duration = Duration::from_millis(500);
const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

// ── TCP-tunneled tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn voice_tcp_same_channel_routes() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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
    assert_eq!(audio.opus_data.as_ref(), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, alice.session_id);
}

#[tokio::test]
async fn voice_tcp_different_channel_does_not_route() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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

#[tokio::test]
async fn voice_tcp_self_mute_silences_sender() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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

#[tokio::test]
async fn voice_tcp_server_mute_silences_sender() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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

#[tokio::test]
async fn voice_tcp_linked_channel_routes() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(70, "Lobby".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans.add_link(0, 70).await.unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(70).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .send_voice_tcp(0, 5, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let received = bob.recv_voice_tcp(VOICE_DEADLINE).await;
    let audio =
        received.expect("Bob in a linked channel should receive Alice's voice over TCP tunnel");
    assert_eq!(audio.opus_data.as_ref(), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, alice.session_id);
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
async fn voice_udp_same_channel_round_trips_and_decrypts() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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
        audio.opus_data.as_ref(),
        SAMPLE_OPUS,
        "opus payload should round-trip byte-identical through OCB2 + routing"
    );
    assert_eq!(audio.sender_session, alice.session_id);
}

#[tokio::test]
async fn voice_tcp_protobuf_round_trips() {
    // Two 1.5+ clients exchange voice in the official protobuf wire format
    // over the TCP tunnel: Alice sends `[0x00, MumbleUDP.Audio]`; the server
    // routes; Bob receives the same payload re-encoded in protobuf because
    // his declared version is also 1.5.
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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
    assert_eq!(audio.opus_data.as_ref(), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, alice.session_id);
    assert_eq!(
        audio.format,
        PacketFormat::Protobuf,
        "1.5 recipient must receive protobuf-format voice"
    );
}

#[tokio::test]
async fn voice_udp_protobuf_round_trips_and_decrypts() {
    // Same as above but over real UDP/OCB2 — exercises the full protobuf
    // pipeline: client encrypt → server decrypt → protobuf decode →
    // re-encode protobuf for recipient → encrypt → client decrypt.
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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
    assert_eq!(audio.opus_data.as_ref(), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, alice.session_id);
    assert_eq!(
        audio.format,
        PacketFormat::Protobuf,
        "1.5 recipient must receive protobuf-format voice"
    );
}

#[tokio::test]
async fn voice_udp_format_matches_recipient_proto_version() {
    // One sender, two recipients with different declared protocol versions.
    // The server must encode each outbound voice packet in the format the
    // recipient declared via its `Version` message: protobuf for 1.5+,
    // legacy Opus for 1.4 and below.
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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
    let mut charlie = TestClient::connect_with_version(
        &server,
        "charlie",
        None,
        ProtocolVersion::new(1, 4, 0),
    )
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
    assert_eq!(bob_audio.opus_data.as_ref(), SAMPLE_OPUS);
    assert_eq!(bob_audio.sender_session, alice.session_id);
    assert_eq!(
        bob_audio.format,
        PacketFormat::Protobuf,
        "Bob declared 1.5 — server must send protobuf format"
    );

    let charlie_audio = charlie
        .recv_voice_udp(VOICE_DEADLINE)
        .await
        .expect("Charlie (1.4) should receive Alice's voice");
    assert_eq!(charlie_audio.opus_data.as_ref(), SAMPLE_OPUS);
    assert_eq!(charlie_audio.sender_session, alice.session_id);
    assert_eq!(
        charlie_audio.format,
        PacketFormat::Legacy,
        "Charlie declared 1.4 — server must send legacy format"
    );
}

#[tokio::test]
async fn voice_udp_different_channel_does_not_route() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
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
