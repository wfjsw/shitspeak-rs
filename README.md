# ShitSpeak RS

ShitSpeak RS is a Rust implementation of a Mumble compatible voice server. It provides TLS client connections, UDP voice and ping handling, ACL aware channel management, persistent server state, optional WASM authentication, and experimental clustered operation.

The Cargo package name is `shitspeak-rs`.

Certificate-hash privacy is configured with `[privacy].protect_certificate_hashes`.
Use `false` to disable it, `true` or `"irreversible"` for a stable one-way
remap, and `"reversible"` for an AES-based stable remap that can be restored
with the shared secret. Only other users' `UserState.hash` values are remapped
for non-superuser clients; the viewer's own hash is sent unchanged. Configure
the same `[privacy].certificate_hash_secret` on every cluster node, or use
`SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET`.

## Project Status

This project is under active development. The checked in `config.toml` is suitable for local testing and should be reviewed before public deployment. Some web gateway and MoQ settings are present but disabled by default.

## Capabilities

1. Mumble client protocol support over TCP with Rustls.
2. UDP voice and ping support with Mumble voice crypto.
3. Channel, ACL, ban, user state, and text message handling.
4. Channel and client state persistence with snapshots and write ahead logs.
5. Hot reload for selected runtime settings from `config.toml`.
6. Optional pluggable authentication through Wasmtime modules.
7. Server to server transport, overlay routing, and replication components for clustered deployments.
8. Browser gateway scaffolding for WebRTC signaling and optional MoQ transport work.
9. Criterion benchmarks for ACL and voice path performance.

## Repository Layout

1. `src/main.rs` contains the binary entry point, logging setup, config loading, authenticator setup, config watching, and graceful shutdown.
2. `src/server.rs` contains the main server accept loops, runtime state, reload handling, web gateway startup, and client orchestration.
3. `src/client` contains client session state, message handlers, voice targets, groups, UDP state, and Mumble voice crypto integration.
4. `src/messages` contains protobuf message reading, writing, and helper macros.
5. `src/voice` contains UDP voice packet decoding, encoding, ping handling, routing, and datagram batching.
6. `src/s2s` contains the server to server transport, overlay, replication, status, and test support modules.
7. `src/web` contains browser signaling, peer session, protocol, voice, and MoQ gateway code.
8. `src/protos` contains the Mumble and internal server to server protobuf definitions.
9. `examples` contains certificate generation examples and WASM authenticator examples.
10. `deploy/docker-compose-16node` contains a local Docker Compose 16 node demo generator.
11. `web/demo` and `web/sdk` contain browser demo and JavaScript SDK assets.
12. `benches` contains Criterion benchmark suites.

## Prerequisites

1. Rust stable with Cargo.
2. A C toolchain suitable for native Rust dependencies on the target platform.
3. PowerShell if you plan to use the included deployment scripts from Windows or PowerShell Core.
4. Node.js and npm only if you plan to build the AssemblyScript WASM authenticator example.
5. The Rust `wasm32-unknown-unknown` target only if you plan to build the Rust WASM authenticator example.

The build uses `prost-build` and `protoc-bin-vendored`, so a separate system Protobuf compiler is not normally required.

## Quick Start

Generate local test certificates:

```powershell
cargo run --example gen-test-certs
```

Check and build the server:

```powershell
cargo check
cargo build
```

Start the server from the repository root:

```powershell
cargo run
```

The default local configuration listens on `0.0.0.0:64738`. Connect a Mumble client to `localhost` on port `64738`. The generated test certificate is intended for local development only.

To increase logging during development:

```powershell
$env:RUST_LOG = "debug"
cargo run
```

To ship logs directly to Grafana Loki, enable `[logging.loki]` in `config.toml`
or set equivalent `SHITSPEAK_LOGGING_LOKI_*` environment variables:

```toml
[logging.loki]
enabled = true
url = "http://localhost:3100"
filter = "shitspeak_rs=debug"
labels = { environment = "dev" }
```

If `filter` is omitted, Loki shipping defaults to `shitspeak_rs=<level>`, so
dependency logs are not sent unless you widen the directive explicitly. Failed
pushes are retried from a bounded in-memory cache; tune
`retry_cache_capacity`, `retry_initial_interval_ms`, and
`retry_max_interval_ms` for larger deployments.

## Configuration

The server loads `config.toml` from the working directory. Values can also be overridden with environment variables using the `SHITSPEAK_` prefix and underscores for nested keys.

Important local settings include:

1. `listen` is the Mumble client TCP and UDP listener address.
2. `cert_path` and `key_path` point to the TLS identity used for client connections.
3. `max_users`, `max_bandwidth`, and message length settings control client limits.
4. `root_channel_name` sets the display name for channel `0`.
5. `udp_voice_enabled` and `udp_ping_enabled` control UDP behavior.
6. `blob_storage_dir` controls where persistent channel, client, and blob data is stored.
7. `authenticator_wasm_path` enables a custom WASM authentication module.
8. `s2s` sections configure clustered server operation.
9. `web` sections configure the browser gateway.
10. `[acl].explicit_enter_deny_overrides_write` lets an explicit `Enter` deny override `Write`'s implied `Enter` permission.
11. `[acl].preserve_write_acl_on_edit` controls whether registered non-superuser ACL editors keep a personal `Write` fallback.
12. `[privacy].protect_certificate_hashes` accepts `false`, `true`, `"irreversible"`, or `"reversible"` for other users' `UserState.hash` values in non-superuser views. Configure the same `[privacy].certificate_hash_secret` on every cluster node, or use `SHITSPEAK_PRIVACY_CERTIFICATE_HASH_SECRET`.

Selected settings are hot reloaded when `config.toml` changes. The C2S TLS identity from `cert_path` and `key_path` is also hot reloaded for new client handshakes when either file changes. Existing TLS sessions continue using the identity they negotiated. Listener addresses, node identity, storage paths, and other startup resources require a restart.

## Authentication

If `authenticator_wasm_path` is omitted, the server uses the built in demo authenticator. For real deployments, provide a WASM authenticator that implements the host contract documented in `wasm_authenticator.md`.

Examples are available in:

1. `examples/wasm-auth-rust`
2. `examples/wasm-auth-assemblyscript`

Build the Rust example:

```powershell
rustup target add wasm32-unknown-unknown
cargo build --manifest-path examples/wasm-auth-rust/Cargo.toml --target wasm32-unknown-unknown --release
```

Build the AssemblyScript example:

```powershell
cd examples/wasm-auth-assemblyscript
npm install
npm run build
```

When a configured WASM file changes, the reload path compiles the new module first. If the new module cannot be loaded, the current authenticator remains active.

## Persistence

The default `blob_storage_dir` is `data`. This directory stores channel snapshots, write ahead logs, channel blobs, session blob cache data, and `user_channel_cache.json` for TTL-bound last/listening channel restoration. For any durable deployment, back up this directory and place it on storage that survives process and host restarts.

The main tunables are:

1. `channel_log_max_entries`
2. `client_log_max_entries`
3. `channel_snapshot_every_ops`
4. `channel_snapshot_every_secs`
5. `channel_wal_compaction_expire_count`

## Server To Server Operation

The server to server subsystem supports multi node operation with transport metrics, overlay routing, state replication, and content addressed channel blob transfer. Configuration is split across `[s2s]`, `[s2s.transport]`, `[s2s.overlay]`, and `[s2s.replications]`.

A clustered deployment must provide unique S2S certificates whose leaf certificate Common Name is the numeric node id, plus listener addresses, advertised addresses, seed peers, and a persistence directory for cluster state. When S2S is disabled or no S2S certificate is configured, the local node id defaults to `0`. When `s2s.persistence_dir` is set, the transport also caches the latest learned adaptive compression dictionary under that directory and renegotiates it with peers after restart. The included Docker Compose demo shows one concrete 16 node layout.

Generate S2S test certificates with:

```powershell
cargo run --example gen-s2s-certs
```

## Browser Gateway

The `[web]` configuration controls the browser gateway. It is disabled by default in `config.toml`.

The gateway related code includes:

1. WebSocket signaling and authentication policy support.
2. WebRTC peer and voice bridge modules.
3. Optional MoQ and WebTransport support behind the Cargo `moq` feature.
4. A small browser demo under `web/demo`.
5. JavaScript SDK assets under `web/sdk`.

Build with MoQ support when needed:

```powershell
cargo build --features moq
```

## Development

Common commands:

```powershell
cargo fmt
cargo check
cargo test
cargo bench
```

The VS Code workspace includes tasks for certificate generation, `cargo check`, and `cargo build`. The default launch profile generates local certificates before starting the debug server.

## Deployment

The `examples/docker-compose-16node` directory contains a committed 16 node Docker Compose demo. It builds a local cluster layout with one server per node, per node S2S certificates with numeric Common Names, shared client TLS material, generated config, and deterministic host port assignments.

Build the Linux musl binary from the repository root first:

```powershell
cross build --target=x86_64-unknown-linux-musl --release
```

Generate or refresh the Compose material:

```powershell
pwsh examples/docker-compose-16node/generate-compose-16node.ps1 -Force
```

Start the cluster:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml up -d --build
```

Useful follow up commands:

```powershell
docker compose -f examples/docker-compose-16node/compose.yaml ps
docker compose -f examples/docker-compose-16node/compose.yaml logs -f node-01
docker compose -f examples/docker-compose-16node/compose.yaml down -v
```

The generator writes `compose.yaml`, the image bundle, shared certificates, per node config and S2S key material, and `manifest.json` with host port assignments.

Node `N` publishes Mumble TCP and UDP on `localhost:20000 + N` and the S2S status page on `localhost:21000 + N`. For example, node 1 is reachable at `localhost:20001`, and its status page is available at `http://localhost:21001`.

## Security Notes

1. Do not use generated test certificates for production.
2. Protect TLS private keys, S2S keys, authentication modules, and persistent data.
3. Configure `allowed_proxies` only for trusted PROXY protocol senders.
4. Use a production authenticator instead of the demo authenticator for any exposed service.
5. Review public registration settings before enabling server list registration.

## License

No license file is included in this repository.
