# Voice Processing Architecture

## Voice Codec (src/voice/codec.rs)
- `PacketFormat` enum — UDPTunnel, Protobuf, Legacy
- `UdpPacket` enum — Audio, Ping, Invalid
- `DecodedAudio` struct — decoded audio frames
- `DecodeError` enum
- Functions: `decode_udp_packet`, `try_decode_protobuf`, `decode_audio_packet`, `decode_audio_protobuf`, `decode_audio_legacy`, `encode_audio_packet`, `encode_audio_protobuf`, `encode_audio_legacy`
- Varint helpers: `read_varint`, `write_varint`

## Voice Ping (src/voice/ping.rs)
- `PingRequest`, `PingResponse` structs
- `try_decode_ping`, `decode_ping_protobuf`, `decode_ping_legacy`
- `encode_ping_response`, `encode_ping_protobuf`, `encode_ping_legacy`

## Voice Routing (src/voice/routing.rs)
- `route_voice` — main voice routing function
- `flush_voice_batch` — flush queued voice packets
- `collect_subtree_ids` — collect channel subtree for voice distribution

## UDP Batching (src/voice/udp_batch.rs)
- `QueuedDatagram` struct
- `flush_batch` — flush batched UDP datagrams
- `send_each` — send individual datagrams
- `sendmmsg_linux` — Linux-specific sendmmsg optimization
- `socket_addr_to_sockaddr_in6` — address conversion

## Voice Crypto (src/voice_crypto/mod.rs)
- `CryptoProvider` trait — interface for voice encryption/decryption

## Client Crypt (src/client/crypt/)
- `CryptState` — per-client voice crypto state with decrypt history
- `CryptoMode` trait — abstraction over crypto algorithms
- `Ocb2` — OCB2 implementation (Mumble's voice crypto)
- `CryptError` enum
