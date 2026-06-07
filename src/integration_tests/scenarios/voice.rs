//! Voice routing scenarios.
//!
//! Each scenario exists in two flavors: TCP-tunneled (sender writes
//! `Message::UDPTunnel`, server fans out to the per-recipient TCP voice
//! queue) and real UDP (sender encrypts with OCB2 and sends via a UDP
//! socket; recipient receives, decrypts, decodes).

use std::time::Duration;

use bytes::Bytes;

use crate::channels::Channel;
use crate::constants::PROTOBUF_INTRODUCED_VERSION;
use crate::integration_tests::harness::{TestClient, TestServerOpts, spawn_test_server};
use crate::messages::encoder::VoiceTarget;
use crate::mumble_proto::voice_target::Target as VoiceTargetEntry;
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

fn voice_target(slot: u32, targets: Vec<VoiceTargetEntry>) -> VoiceTarget {
    VoiceTarget {
        id: Some(slot),
        targets,
    }
}

fn voice_target_user(session: u32) -> VoiceTargetEntry {
    VoiceTargetEntry {
        session: vec![session],
        channel_id: None,
        group: None,
        links: Some(false),
        children: Some(false),
    }
}

fn voice_target_channel(
    channel_id: u32,
    children: bool,
    links: bool,
    group: Option<&str>,
) -> VoiceTargetEntry {
    VoiceTargetEntry {
        session: Vec::new(),
        channel_id: Some(channel_id),
        group: group.map(str::to_owned),
        links: Some(links),
        children: Some(children),
    }
}

async fn expect_voice_from(recipient: &TestClient, sender: &TestClient, reason: &str) {
    let audio = recipient
        .recv_voice_tcp(VOICE_DEADLINE)
        .await
        .expect(reason);
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(sender.server_session));
}

async fn expect_no_voice(recipient: &TestClient, reason: &str) {
    assert!(
        recipient.recv_voice_tcp(NEGATIVE_WINDOW).await.is_none(),
        "{reason}"
    );
}

// ── TCP-tunneled tests ──────────────────────────────────────────────────────

/// Checks regular TCP-tunneled voice routing within one channel.
/// Expected: Bob receives Alice's Opus payload with Alice's server session as
/// sender. Mumble routes `UDPTunnel` audio through `D:\mumble\src\murmur\Server.cpp::processMsg`;
/// shitspeak mirrors regular voice broadcast in `D:\shitspeak\client.go` and
/// `D:\shitspeak\message.go`.
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

/// Checks that regular voice is not routed to users in unrelated channels.
/// Expected: after Bob moves to another channel, he receives no TCP-tunneled
/// voice from Alice. This comes from Mumble's channel-scoped receiver selection
/// in `D:\mumble\src\murmur\Server.cpp::processMsg` and shitspeak's voice
/// target selection in `D:\shitspeak\client.go`.
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

/// Checks that self-muted users cannot send voice.
/// Expected: Bob receives no audio from Alice while Alice has `self_mute`.
/// Mumble drops muted/self-muted senders at the top of
/// `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak applies the same
/// sender gate in `D:\shitspeak\client.go`.
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

/// Checks that server-muted users cannot send voice.
/// Expected: Alice receives no audio from Bob after Alice sets Bob's server
/// mute. Mumble's `processMsg` returns for `bMute`, and shitspeak's voice path
/// checks the corresponding `Mute` state in `D:\shitspeak\client.go`.
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

/// Checks that regular speech crosses effective linked-channel groups.
/// Expected: Bob receives Alice's normal-channel voice through a link chain.
/// Mumble explicitly walks linked channels with Speak permission in
/// `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak exposes the same
/// linked-channel voice-target behavior through `D:\shitspeak\voicetarget.go`.
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
    chans
        .create_channel(Channel::new(71, "Side".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans.add_link(0, 70).await.unwrap();
    chans.add_link(70, 71).await.unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");

    bob.move_to_channel(71).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .send_voice_tcp(0, 5, Bytes::from_static(SAMPLE_OPUS))
        .await;

    let received = bob.recv_voice_tcp(VOICE_DEADLINE).await;
    let audio = received.expect(
        "Bob in a transitively linked channel should receive Alice's voice over TCP tunnel",
    );
    assert_eq!(opus_frame(&audio.audio_payload), SAMPLE_OPUS);
    assert_eq!(audio.sender_session, Some(alice.server_session));
}

/// Checks direct-user voice targets.
/// Expected: only the targeted session receives the packet.
#[tokio::test]
async fn voice_target_to_user_whispers_only_to_that_session() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(90, "WhisperTarget".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(90).await;
    carol.move_to_channel(90).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(7, vec![voice_target_user(bob.session_id)]))
        .await;
    alice
        .send_voice_tcp(7, 31, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(&bob, &alice, "Bob should receive direct voice target audio").await;
    expect_no_voice(
        &carol,
        "Carol should not receive audio targeted only at Bob's session",
    )
    .await;
}

/// Checks channel voice targets without child or link expansion.
/// Expected: users in the target channel receive shout audio; users in child
/// channels do not.
#[tokio::test]
async fn voice_target_to_channel_shouts_only_to_that_channel() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(100, "TargetChannel".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(101, "TargetChild".to_owned(), 0, 0, Some(100)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(100).await;
    carol.move_to_channel(101).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(100, false, false, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 32, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(&bob, &alice, "Bob should receive channel shout audio").await;
    expect_no_voice(
        &carol,
        "Carol in a child channel should not receive a non-recursive channel target",
    )
    .await;
}

/// Checks child-channel expansion for channel voice targets.
/// Expected: users in descendant channels receive shout audio when
/// `children` is enabled.
#[tokio::test]
async fn voice_target_to_children_shouts_to_descendants() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(110, "Parent".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(111, "Child".to_owned(), 0, 0, Some(110)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(112, "Elsewhere".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(111).await;
    carol.move_to_channel(112).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(110, true, false, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 33, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob in a child channel should receive recursive channel target audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol in an unrelated channel should not receive recursive channel target audio",
    )
    .await;
}

/// Checks linked-channel expansion for channel voice targets.
/// Expected: users in linked channels receive shout audio when `links` is
/// enabled.
#[tokio::test]
async fn voice_target_to_linked_channels_shouts_across_links() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec![]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(120, "LinkSource".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(121, "Linked".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans
        .create_channel(Channel::new(122, "Unlinked".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();
    chans.add_link(120, 121).await.unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(121).await;
    carol.move_to_channel(122).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(120, false, true, None)],
        ))
        .await;
    alice
        .send_voice_tcp(7, 34, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob in a linked channel should receive linked voice target audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol in an unlinked channel should not receive linked voice target audio",
    )
    .await;
}

/// Checks group filtering for channel voice targets.
/// Expected: only recipients whose authenticated groups match the target's
/// `group` field receive shout audio.
#[tokio::test]
async fn voice_target_to_specific_group_filters_recipients() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);
    server
        .authenticator
        .register_user("bob", None, Some(2), vec!["casters".into()]);
    server
        .authenticator
        .register_user("carol", None, Some(3), vec![]);

    let chans = server.server.get_channels();
    chans
        .create_channel(Channel::new(130, "Grouped".to_owned(), 0, 0, Some(0)))
        .await
        .unwrap();

    let alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");
    let bob = TestClient::connect_and_authenticate(&server, "bob", None)
        .await
        .expect("bob");
    let carol = TestClient::connect_and_authenticate(&server, "carol", None)
        .await
        .expect("carol");

    bob.move_to_channel(130).await;
    carol.move_to_channel(130).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    alice
        .set_voice_target(voice_target(
            7,
            vec![voice_target_channel(130, false, false, Some("casters"))],
        ))
        .await;
    alice
        .send_voice_tcp(7, 35, Bytes::from_static(SAMPLE_OPUS))
        .await;

    expect_voice_from(
        &bob,
        &alice,
        "Bob should receive group-filtered voice target audio",
    )
    .await;
    expect_no_voice(
        &carol,
        "Carol should not receive voice target audio for a group she is not in",
    )
    .await;
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
async fn voice_udp_ping_echoes_encrypted_timestamp() {
    let server = spawn_test_server(TestServerOpts::default()).await;
    server
        .authenticator
        .register_user("alice", None, Some(1), vec!["admin".into()]);

    let mut alice = TestClient::connect_and_authenticate(&server, "alice", None)
        .await
        .expect("alice");

    alice.open_udp().await.expect("alice udp bind");
    alice.udp_handshake().await.expect("alice udp ping");

    let ping = alice
        .recv_udp_ping(VOICE_DEADLINE)
        .await
        .expect("encrypted udp ping response");
    assert_eq!(ping.timestamp, 1);
    assert_eq!(ping.format, PacketFormat::Legacy);
}

/// Checks real UDP voice routing, encryption, and decryption for one channel.
/// Expected: Bob decrypts Alice's byte-identical Opus payload and sender
/// session. This follows Mumble's UDP decrypt/route/encrypt path in
/// `D:\mumble\src\murmur\Server.cpp::run` and `processMsg`, and shitspeak's
/// OCB2 UDP path in `D:\shitspeak\client.go` plus `D:\shitspeak\cryptstate`.
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

/// Checks TCP-tunneled voice using the Mumble 1.5 protobuf audio format.
/// Expected: a 1.5 recipient receives protobuf-format audio with the same Opus
/// frame and sender session. The wire format comes from
/// `D:\mumble\src\MumbleUDP.proto` and Mumble protocol handling; shitspeak
/// keeps the same generated protocol surface in `D:\shitspeak\mumbleproto`.
#[tokio::test]
async fn voice_tcp_protobuf_round_trips() {
    // Two 1.5+ clients exchange voice in the official protobuf wire format
    // over the TCP tunnel: Alice sends `[0x00, MumbleUDP.Audio]`; the server
    // routes; Bob receives the same payload re-encoded in protobuf because
    // his declared version is also 1.5.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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

/// Checks UDP voice using the Mumble 1.5 protobuf audio format.
/// Expected: the full encrypt/decrypt routing path preserves the Opus payload
/// and returns protobuf-format audio to a 1.5 recipient. This is sourced from
/// `D:\mumble\src\MumbleUDP.proto`, `D:\mumble\src\murmur\Server.cpp::run`,
/// and shitspeak's UDP crypt/protocol path in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_udp_protobuf_round_trips_and_decrypts() {
    // Same as above but over real UDP/OCB2 — exercises the full protobuf
    // pipeline: client encrypt → server decrypt → protobuf decode →
    // re-encode protobuf for recipient → encrypt → client decrypt.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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

/// Checks per-recipient voice encoding based on declared protocol version.
/// Expected: Bob declaring 1.5 receives protobuf voice, while Charlie declaring
/// 1.4 receives legacy voice from the same send. Mumble sets protocol-version
/// aware UDP encoders in `D:\mumble\src\murmur\Server.cpp`; shitspeak's generated
/// `D:\shitspeak\mumbleproto` and client version handling provide the parity source.
#[tokio::test]
async fn voice_udp_format_matches_recipient_proto_version() {
    // One sender, two recipients with different declared protocol versions.
    // The server must encode each outbound voice packet in the format the
    // recipient declared via its `Version` message: protobuf for 1.5+,
    // legacy Opus for 1.4 and below.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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
    let mut charlie =
        TestClient::connect_with_version(&server, "charlie", None, ProtocolVersion::new(1, 4, 0))
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

/// Checks that the server protocol version gates protobuf voice output before
/// recipient capability is considered.
#[tokio::test]
async fn voice_server_protocol_version_gates_protobuf_voice() {
    async fn run_case(
        server_protocol_version: ProtocolVersion,
        bob_version: ProtocolVersion,
        charlie_version: ProtocolVersion,
        expected_bob: PacketFormat,
        expected_charlie: PacketFormat,
    ) {
        let server = spawn_test_server(TestServerOpts {
            server_protocol_version,
            ..TestServerOpts::default()
        })
        .await;
        server
            .authenticator
            .register_user("alice", None, Some(1), vec!["admin".into()]);
        server
            .authenticator
            .register_user("bob", None, Some(2), vec![]);
        server
            .authenticator
            .register_user("charlie", None, Some(3), vec![]);

        let alice =
            TestClient::connect_with_version(&server, "alice", None, PROTOBUF_INTRODUCED_VERSION)
                .await
                .expect("alice");
        let bob = TestClient::connect_with_version(&server, "bob", None, bob_version)
            .await
            .expect("bob");
        let charlie = TestClient::connect_with_version(&server, "charlie", None, charlie_version)
            .await
            .expect("charlie");

        alice
            .send_voice_tcp_protobuf(0, 22, Bytes::from_static(SAMPLE_OPUS))
            .await;

        let bob_audio = bob
            .recv_voice_tcp(VOICE_DEADLINE)
            .await
            .expect("Bob should receive Alice's voice over TCP tunnel");
        assert_eq!(opus_frame(&bob_audio.audio_payload), SAMPLE_OPUS);
        assert_eq!(bob_audio.sender_session, Some(alice.server_session));
        assert_eq!(bob_audio.format, expected_bob);

        let charlie_audio = charlie
            .recv_voice_tcp(VOICE_DEADLINE)
            .await
            .expect("Charlie should receive Alice's voice over TCP tunnel");
        assert_eq!(opus_frame(&charlie_audio.audio_payload), SAMPLE_OPUS);
        assert_eq!(charlie_audio.sender_session, Some(alice.server_session));
        assert_eq!(charlie_audio.format, expected_charlie);
    }

    run_case(
        ProtocolVersion::new(1, 4, 0),
        PROTOBUF_INTRODUCED_VERSION,
        PROTOBUF_INTRODUCED_VERSION,
        PacketFormat::Legacy,
        PacketFormat::Legacy,
    )
    .await;
    run_case(
        PROTOBUF_INTRODUCED_VERSION,
        PROTOBUF_INTRODUCED_VERSION,
        ProtocolVersion::new(1, 4, 0),
        PacketFormat::Protobuf,
        PacketFormat::Legacy,
    )
    .await;
}

/// Checks legacy UDP voice when both clients declare pre-1.5 protocol support.
/// Expected: Bob receives legacy-format Opus with Alice's sender session. This
/// is the Mumble 1.4-compatible path in `D:\mumble\src\murmur\Server.cpp::run`
/// and `processMsg`, mirrored by shitspeak's legacy packet handling in
/// `D:\shitspeak\client.go`.
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

/// Checks that UDP voice obeys the same channel isolation as TCP voice.
/// Expected: Bob in a different channel receives no UDP audio from Alice. The
/// behavior comes from Mumble's receiver selection in
/// `D:\mumble\src\murmur\Server.cpp::processMsg` and shitspeak's regular voice
/// routing in `D:\shitspeak\client.go`.
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

/// Checks that the legacy Opus terminator bit survives TCP routing.
/// Expected: Bob receives an Opus payload with `is_terminator = true` and the
/// same frame bytes. The bit is defined by Mumble's legacy UDP/TCP audio format
/// in `D:\mumble\src\MumbleProtocol.*`; shitspeak preserves it in the legacy
/// packet path in `D:\shitspeak\client.go`.
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
    let bob = TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
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

/// Checks that the protobuf Opus terminator flag survives TCP routing.
/// Expected: Bob receives a protobuf-decoded Opus payload with the terminator
/// flag intact. This follows `D:\mumble\src\MumbleUDP.proto`'s audio fields and
/// Mumble routing in `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak
/// uses the same generated Mumble UDP protobuf definitions.
#[tokio::test]
async fn voice_tcp_protobuf_terminator_bit_preserved() {
    // Same invariant as above but through the 1.5+ protobuf pipeline.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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

/// Checks that legacy positional audio data survives TCP routing.
/// Expected: Bob receives the same XYZ coordinates and Opus payload Alice sent.
/// Mumble defines positional audio in the legacy audio packet format and routes
/// it through `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak preserves
/// positional bytes in `D:\shitspeak\client.go`.
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
    let bob = TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
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

/// Checks that protobuf positional audio data survives TCP routing.
/// Expected: Bob receives the same XYZ coordinates and Opus payload from the
/// `MumbleUDP.Audio` protobuf field. The source is `D:\mumble\src\MumbleUDP.proto`
/// and Murmur's voice routing; shitspeak keeps the same protobuf schema under
/// `D:\shitspeak\mumbleproto`.
#[tokio::test]
async fn voice_tcp_protobuf_positional_data_round_trip() {
    // Same as above but through the 1.5+ protobuf pipeline, where positional
    // data is encoded in the MumbleUDP.Audio proto field.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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

/// Checks legacy server loopback target handling.
/// Expected: target 31 echoes the packet only to Alice and not to Bob. Mumble
/// handles `ReservedTargetIDs::SERVER_LOOPBACK` in
/// `D:\mumble\src\murmur\Server.cpp::processMsg`; shitspeak mirrors target 31
/// handling in `D:\shitspeak\client.go`.
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
    let bob = TestClient::connect_with_version(&server, "bob", None, ProtocolVersion::new(1, 4, 0))
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

/// Checks protobuf server loopback target handling.
/// Expected: target 31 echoes protobuf voice only to Alice and does not route it
/// to Bob. This comes from Mumble's reserved server-loopback target in
/// `D:\mumble\src\murmur\Server.cpp::processMsg` and shitspeak's equivalent
/// target handling in `D:\shitspeak\client.go`.
#[tokio::test]
async fn voice_tcp_protobuf_server_loopback() {
    // Same as above but through the 1.5+ protobuf pipeline.
    let server = spawn_test_server(TestServerOpts {
        server_protocol_version: PROTOBUF_INTRODUCED_VERSION,
        ..TestServerOpts::default()
    })
    .await;
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
