Implemented configurable server_protocol_version for APP_PROTO_VER-related behavior and added E2E voice benchmark harness.

Protocol mockability:
- Config.server_protocol_version defaults to APP_PROTO_VER and is used for Version::for_server, UDP ping response server_version, public registration XML, and voice routing protobuf gate.
- TestServerOpts.server_protocol_version defaults to APP_PROTO_VER and can override per integration test.
- voice routing now chooses protobuf only when server_protocol_version >= PROTOBUF_INTRODUCED_VERSION and recipient client uses protobuf.

Tests:
- src/integration_tests/scenarios/voice.rs includes voice_server_protocol_version_gates_protobuf_voice:
  - server 1.4.0 with bob/charlie 1.5.0 => both receive Legacy
  - server 1.5.0 with bob 1.5.0 and charlie 1.4.0 => bob Protobuf, charlie Legacy
- Existing protobuf voice tests explicitly start server with PROTOBUF_INTRODUCED_VERSION because APP_PROTO_VER remains 1.4.0.

Benchmark:
- Cargo.toml registers bench voice_e2e.
- benches/voice_e2e.rs starts a real Server with local PKI, real TLS clients, authentication, and UDP OCB2 setup.
- Matrix: server_1_4_all_legacy, server_1_5_client_1_4_legacy, server_1_5_client_1_5_protobuf for both TCP and UDP.
- Protobuf recipient case sends protobuf client input and verifies protobuf output.
- Metrics printed: delay mean/p50/p95/p99/max, jitter mean/max based on adjacent delay deltas, payload_kbps, wire_kbps, mean_wire_bytes.

Validation run:
- cargo fmt
- cargo check --benches passes, only Windows incremental compilation cleanup Access is denied warning.
- cargo test protobuf -- --nocapture --test-threads=1 passes.
- cargo test voice_server_protocol_version_gates_protobuf_voice -- --nocapture --test-threads=1 passes.
- cargo bench --bench voice_e2e -- voice_e2e/udp_roundtrip/server_1_5_client_1_5_protobuf --noplot --sample-size 10 --measurement-time 1 --warm-up-time 1 passes and prints all six metric rows.

Representative final smoke metrics:
TCP server_1_4_all_legacy mean 108us p95 134us p99 205us wire 2714.52kbps 36B.
TCP server_1_5_client_1_4_legacy mean 117us p95 164us p99 209us wire 2475.72kbps 36B.
TCP server_1_5_client_1_5_protobuf mean 141us p95 191us p99 207us wire 2620.00kbps 46B.
UDP server_1_4_all_legacy mean 179us p95 227us p99 325us wire 1588.87kbps 35B.
UDP server_1_5_client_1_4_legacy mean 168us p95 226us p99 333us wire 1686.01kbps 35B.
UDP server_1_5_client_1_5_protobuf mean 150us p95 204us p99 232us wire 2437.80kbps 45B.

Unrelated dirty files existed in .serena, config.toml, src/blob_store.rs, src/s2s/*, plan exports; do not revert.