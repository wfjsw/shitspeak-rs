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
use crate::voice::codec::{AudioPayload, PacketFormat};

const VOICE_DEADLINE: Duration = Duration::from_secs(2);
const NEGATIVE_WINDOW: Duration = Duration::from_millis(500);
const SAMPLE_OPUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

fn opus_frame(payload: &AudioPayload) -> &[u8] {
    match payload {
        AudioPayload::Opus(p) => &p.frame,
        _ => panic!("expected Opus payload, got {payload:?}"),
    }
}

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
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
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
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
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
        opus_frame(&audio.audio_payload),
        SAMPLE_OPUS,
        "opus payload should round-trip byte-identical through OCB2 + routing"
    );
    assert_eq!(audio.sender_session, Some(alice.server_session));
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
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
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
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
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
    assert_eq!(opus_frame(&bob_audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(bob_audio.sender_session, Some(alice.server_session));
    assert_eq!(
        bob_audio.format,
        PacketFormat::Protobuf,
        "Bob declared 1.5 — server must send protobuf format"
    );

    let charlie_audio = charlie
        .recv_voice_udp(VOICE_DEADLINE)
        .await
        .expect("Charlie (1.4) should receive Alice's voice");
    assert_eq!(opus_frame(&charlie_audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(charlie_audio.sender_session, Some(alice.server_session));
    assert_eq!(
        charlie_audio.format,
        PacketFormat::Legacy,
        "Charlie declared 1.4 — server must send legacy format"
    );
}

#[tokio::test]
async fn voice_udp_legacy_to_legacy_round_trips() {
    // Both clients declare 1.4 → both speak legacy. Reproduces the path the
    // real Mumble 1.4.x client uses: legacy in, legacy out.
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let mut alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("alice");
    let mut bob =
        TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("bob");

    open_udp_pair(&mut alice, &mut bob).await;

    alice
        .send_voice_udp(0, 100, Bytes::from_static(SAMPLE_OPUS))
        .await
        .expect("alice send_voice_udp legacy");

    let audio = bob
        .recv_voice_udp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.4) should receive Alice's legacy voice over UDP");
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
    assert_eq!(audio.format, PacketFormat::Legacy);
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

// ── Legacy-specific packet behaviors (pre-protobuf / 1.4 clients) ───────────

#[tokio::test]
async fn voice_tcp_legacy_terminator_bit_preserved() {
    // Opus terminator bit (0x2000 in the legacy size_flag) must survive the
    // server routing pipeline. Doc: "The 14th bit (mask: 0x2000) is the
    // terminator bit which signals whether the packet is the last one in the
    // voice transmission."
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("alice");
    let bob =
        TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("bob");

    alice
        .send_voice_tcp_terminator(0, 50, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.4) should receive Alice's terminator frame");
    let AudioPayload::Opus(p) = &audio.audio_payload else {
        panic!("expected Opus payload, got {:?}", audio.audio_payload);
    };
    assert!(
        p.is_terminator,
        "terminator bit must survive the server routing pipeline"
    );
    assert_eq!(p.frame.as_ref(), SAMPLE_OPUS);
}

#[tokio::test]
async fn voice_tcp_protobuf_terminator_bit_preserved() {
    // Same invariant as above but through the 1.5+ protobuf pipeline.
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
        .send_voice_tcp_protobuf_terminator(0, 51, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.5) should receive Alice's terminator frame");
    let AudioPayload::Opus(p) = &audio.audio_payload else {
        panic!("expected Opus payload, got {:?}", audio.audio_payload);
    };
    assert!(
        p.is_terminator,
        "terminator bit must survive the server routing pipeline (protobuf)"
    );
    assert_eq!(p.frame.as_ref(), SAMPLE_OPUS);
}

#[tokio::test]
async fn voice_tcp_legacy_positional_data_round_trip() {
    // Positional audio (optional 3 × f32 XYZ appended after the Opus payload
    // in the legacy wire format) must survive server routing unchanged.
    // Doc: "The XYZ coordinates of the audio source."
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("alice");
    let bob =
        TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("bob");

    let positional = [1.5_f32, 2.5, 3.5];
    alice
        .send_voice_tcp_with_positional(0, 60, Bytes::from_static(SAMPLE_OPUS), positional)
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.4) should receive Alice's voice with positional data");
    assert_eq!(
        audio.positional_data,
        Some(positional),
        "positional XYZ must survive legacy routing unchanged"
    );
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
}

#[tokio::test]
async fn voice_tcp_protobuf_positional_data_round_trip() {
    // Same as above but through the 1.5+ protobuf pipeline, where positional
    // data is encoded in the MumbleUDP.Audio proto field.
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

    let positional = [4.0_f32, 5.0, 6.0];
    alice
        .send_voice_tcp_protobuf_with_positional(0, 61, Bytes::from_static(SAMPLE_OPUS), positional)
        .await;

    let audio = bob
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Bob (1.5) should receive Alice's voice with positional data");
    assert_eq!(
        audio.positional_data,
        Some(positional),
        "positional XYZ must survive protobuf routing unchanged"
    );
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
}

#[tokio::test]
async fn voice_tcp_legacy_server_loopback() {
    // target=31 (Server Loopback) must echo the packet back to the sender;
    // other channel members must not receive it. Doc: "Server Loopback (31)".
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);

    let alice =
        TestClient::connect_with_version(&server, "alice", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("alice");
    let bob =
        TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
            .await
            .expect("bob");

    alice
        .send_voice_tcp(31, 70, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let echo = alice
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Alice should receive her own loopback packet (legacy)");
    assert_eq!(
        opus_frame(&echo.audio_payload),
        SAMPLE_OPUS,
        "loopback must echo the original audio payload"
    );

    let received_by_bob = bob.recv_voice_tcp(NEGATIVE_WINDOW).await;
    assert!(
        received_by_bob.is_none(),
        "Bob must not receive the server loopback packet"
    );
}

#[tokio::test]
async fn voice_tcp_protobuf_server_loopback() {
    // Same as above but through the 1.5+ protobuf pipeline.
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
        .send_voice_tcp_protobuf(31, 71, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let echo = alice
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect("Alice should receive her own loopback packet (protobuf)");
    assert_eq!(
        opus_frame(&echo.audio_payload),
        SAMPLE_OPUS,
        "loopback must echo the original audio payload"
    );

    let received_by_bob = bob.recv_voice_tcp(NEGATIVE_WINDOW).await;
    assert!(
        received_by_bob.is_none(),
        "Bob must not receive the server loopback packet"
    );
}
