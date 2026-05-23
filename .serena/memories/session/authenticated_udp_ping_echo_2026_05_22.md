# Authenticated UDP Ping Echo Fix (2026-05-22)

Connected clients send encrypted UDP ping packets on the voice socket to measure UDP RTT and then report `udp_ping_avg` / `udp_ping_var` in TCP `Ping` messages. The server previously decoded authenticated UDP pings in `Server::spawn_udp_process` but replied with `Server::build_ping_response`, which is the unauthenticated server-list ping response and was sent unencrypted. Real clients could not use that to calculate UDP average/deviation.

Implemented `PingRequest::encode_authenticated_echo()` in `src/voice/ping.rs` to encode an echo ping in the authenticated UDP packet format:
- protobuf: `0x01 + MumbleUDP.Ping { timestamp, ..default }`
- legacy: `0x20 + PDS-varint timestamp`

Updated `Server::spawn_udp_process` to encrypt that echo with the matched client's `CryptState` before `send_to`. The existing unauthenticated UDP server-list ping path in `spawn_udp_drain` still uses `build_ping_response` and remains unchanged.

Added codec tests for legacy/protobuf authenticated echoes and integration test `voice_udp_ping_echoes_encrypted_timestamp` with `TestClient::recv_udp_ping()`. Targeted commands passed:
- `cargo test authenticated_`
- `cargo test voice_udp_ping_echoes_encrypted_timestamp`

Note: cargo emitted a Windows incremental compilation warning: `error finalizing incremental compilation session directory ... Access is denied`, but tests passed.